//! Tree walk and permission application.

use std::fs;
use std::io;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::exec;
use crate::mode;

/// Walk and fix options.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Options {
    /// Report changes without applying them.
    pub dry_run: bool,
}

/// What happened (or, under dry-run, would happen) to one entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// The mode was changed (or, under dry-run, would be changed).
    Changed { from: u32, to: u32 },
    /// The mode already matched; nothing was done.
    Unchanged { mode: u32 },
    /// Not processed: symlink, special file, or a mount point.
    Skipped { reason: &'static str },
    /// Per-entry failure; the walk continues.
    Error { message: String },
}

/// One entry of the walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub path: PathBuf,
    pub action: Action,
}

/// Aggregate counts over a walk's results.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Report {
    pub checked: usize,
    pub changed: usize,
    pub skipped: usize,
    pub errors: usize,
}

/// Walk `root` and normalize permissions to umask-derived values.
///
/// The walk stays on the filesystem containing `root`: directories on other
/// devices (mount points) are themselves processed but not descended into,
/// like `find -xdev`. Symlinks are never followed and never changed. A root
/// that is itself a symlink *is* followed, so passing a link to a directory
/// behaves like passing the directory. Per-entry failures are recorded as
/// [`Action::Error`] and the walk continues.
pub fn run(root: &Path, umask: u32, opts: &Options) -> Result<Vec<Entry>, io::Error> {
    let root_meta = fs::metadata(root).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("cannot access {}: {err}", root.display()),
        )
    })?;
    let mut entries = Vec::new();
    apply_entry(root, &root_meta, umask, opts, &mut entries);
    if root_meta.is_dir() {
        walk(root, root_meta.dev(), umask, opts, &mut entries);
    }
    Ok(entries)
}

/// Aggregate counts over a walk's results.
pub fn report(entries: &[Entry]) -> Report {
    let mut rep = Report::default();
    for entry in entries {
        match entry.action {
            Action::Changed { .. } => {
                rep.checked += 1;
                rep.changed += 1;
            }
            Action::Unchanged { .. } => rep.checked += 1,
            Action::Skipped { .. } => rep.skipped += 1,
            Action::Error { .. } => rep.errors += 1,
        }
    }
    rep
}

fn apply_entry(
    path: &Path,
    meta: &fs::Metadata,
    umask: u32,
    opts: &Options,
    entries: &mut Vec<Entry>,
) {
    let is_dir = meta.is_dir();
    let current = meta.mode() & 0o7777;

    // The exec bit can only matter if the umask-derived base mode keeps a
    // read bit somewhere; otherwise detection cannot change the outcome.
    let executable = if !is_dir && (mode::file_mode(umask) & 0o444) != 0 {
        match exec::detect(path) {
            Ok(found) => found,
            Err(err) => {
                entries.push(Entry {
                    path: path.to_path_buf(),
                    action: Action::Error {
                        message: format!("cannot inspect for shebang/ELF: {err}"),
                    },
                });
                false
            }
        }
    } else {
        false
    };

    let desired = mode::merge(current, mode::desired_mode(umask, is_dir, executable));
    if current == desired {
        entries.push(Entry {
            path: path.to_path_buf(),
            action: Action::Unchanged { mode: current },
        });
        return;
    }
    if opts.dry_run {
        entries.push(Entry {
            path: path.to_path_buf(),
            action: Action::Changed {
                from: current,
                to: desired,
            },
        });
        return;
    }
    match fs::set_permissions(path, fs::Permissions::from_mode(desired)) {
        Ok(()) => entries.push(Entry {
            path: path.to_path_buf(),
            action: Action::Changed {
                from: current,
                to: desired,
            },
        }),
        Err(err) => entries.push(Entry {
            path: path.to_path_buf(),
            action: Action::Error {
                message: format!("cannot set permissions: {err}"),
            },
        }),
    }
}

fn walk(dir: &Path, root_dev: u64, umask: u32, opts: &Options, entries: &mut Vec<Entry>) {
    let read_dir = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(err) => {
            entries.push(Entry {
                path: dir.to_path_buf(),
                action: Action::Error {
                    message: format!("cannot read directory: {err}"),
                },
            });
            return;
        }
    };
    // Sorted order keeps the report deterministic (readdir order is not).
    let mut paths: Vec<PathBuf> = read_dir
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .collect();
    paths.sort();
    for path in paths {
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(err) => {
                entries.push(Entry {
                    path: path.clone(),
                    action: Action::Error {
                        message: format!("cannot stat: {err}"),
                    },
                });
                continue;
            }
        };
        if meta.is_dir() {
            apply_entry(&path, &meta, umask, opts, entries);
            if same_device(root_dev, meta.dev()) {
                walk(&path, root_dev, umask, opts, entries);
            } else {
                entries.push(Entry {
                    path: path.clone(),
                    action: Action::Skipped {
                        reason: "mount point; not descending",
                    },
                });
            }
        } else if meta.is_file() {
            apply_entry(&path, &meta, umask, opts, entries);
        } else {
            entries.push(Entry {
                path: path.clone(),
                action: Action::Skipped {
                    reason: describe(&meta.file_type()),
                },
            });
        }
    }
}

/// Whether a directory on device `dev` sits on the same filesystem as the
/// root device (i.e. whether the walk may descend into it).
pub fn same_device(root_dev: u64, dev: u64) -> bool {
    root_dev == dev
}

fn describe(file_type: &fs::FileType) -> &'static str {
    if file_type.is_symlink() {
        "symlink"
    } else if file_type.is_fifo() {
        "FIFO"
    } else if file_type.is_socket() {
        "socket"
    } else if file_type.is_block_device() {
        "block device"
    } else if file_type.is_char_device() {
        "character device"
    } else {
        "special file"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UmaskGuard;
    use crate::exec::fixtures;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, MutexGuard};

    static UMASK_LOCK: Mutex<()> = Mutex::new(());

    /// Serialize tests that mutate the process umask, and restore the
    /// original mask on drop.
    struct MaskGuard {
        _lock: MutexGuard<'static, ()>,
        _mask: UmaskGuard,
    }

    fn mask(m: u32) -> MaskGuard {
        MaskGuard {
            _lock: UMASK_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            _mask: UmaskGuard::set(m),
        }
    }

    fn write_file(path: &Path, contents: &[u8], mode: u32) -> PathBuf {
        std::fs::write(path, contents).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        path.to_path_buf()
    }

    fn make_dir(path: &Path, mode: u32) {
        std::fs::create_dir(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::symlink_metadata(path).unwrap().mode() & 0o7777
    }

    #[test]
    fn same_device_helper() {
        assert!(same_device(7, 7));
        assert!(!same_device(7, 8));
    }

    #[test]
    fn normalizes_files_and_dirs() {
        let _m = mask(0o022);
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // tempdir's own mode depends on mkdtemp/umask; make the starting
        // state explicit.
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
        make_dir(root.join("sub").as_ref(), 0o700);
        write_file(root.join("a.txt").as_ref(), b"a", 0o600);
        write_file(root.join("sub/b.txt").as_ref(), b"b", 0o640);

        let opts = Options { dry_run: false };
        let entries = run(root, 0o022, &opts).unwrap();
        let rep = report(&entries);

        assert_eq!(mode_of(root), 0o755);
        assert_eq!(mode_of(root.join("sub").as_ref()), 0o755);
        assert_eq!(mode_of(root.join("a.txt").as_ref()), 0o644);
        assert_eq!(mode_of(root.join("sub/b.txt").as_ref()), 0o644);
        assert_eq!(rep.checked, 4);
        assert_eq!(rep.changed, 4);
        assert_eq!(rep.skipped, 0);
        assert_eq!(rep.errors, 0);
    }

    #[test]
    fn executables_get_exec_bit() {
        let _m = mask(0o022);
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_file(
            root.join("script.sh").as_ref(),
            b"#!/bin/sh\necho hi\n",
            0o600,
        );
        // ET_DYN with PT_INTERP: a position-independent executable
        write_file(
            root.join("prog").as_ref(),
            &fixtures::elf(3, 2, true, &[(1, 0), (3, 0)], None),
            0o600,
        );
        // ET_DYN without PT_INTERP: a shared object
        write_file(
            root.join("lib.so").as_ref(),
            &fixtures::elf(3, 2, true, &[(1, 0)], Some(&[0u8; 16])),
            0o600,
        );
        // Classic a.out (ZMAGIC): an executable program
        write_file(root.join("legacy").as_ref(), b"\x05\x00\x08\x01", 0o600);
        write_file(root.join("plain.txt").as_ref(), b"hello\n", 0o600);

        run(root, 0o022, &Options::default()).unwrap();

        assert_eq!(mode_of(root.join("script.sh").as_ref()), 0o755);
        assert_eq!(mode_of(root.join("prog").as_ref()), 0o755);
        assert_eq!(mode_of(root.join("lib.so").as_ref()), 0o644);
        assert_eq!(mode_of(root.join("legacy").as_ref()), 0o755);
        assert_eq!(mode_of(root.join("plain.txt").as_ref()), 0o644);
    }

    #[test]
    fn umask_077() {
        let _m = mask(0o077);
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        make_dir(root.join("d").as_ref(), 0o777);
        write_file(root.join("f").as_ref(), b"f", 0o666);
        write_file(root.join("s").as_ref(), b"#!/bin/sh\n", 0o666);
        write_file(
            root.join("p").as_ref(),
            &fixtures::elf(2, 2, true, &[], None),
            0o666,
        );

        run(root, 0o077, &Options::default()).unwrap();

        assert_eq!(mode_of(root.join("d").as_ref()), 0o700);
        assert_eq!(mode_of(root.join("f").as_ref()), 0o600);
        assert_eq!(mode_of(root.join("s").as_ref()), 0o700);
        assert_eq!(mode_of(root.join("p").as_ref()), 0o700);
    }

    #[test]
    fn preserves_special_bits() {
        let _m = mask(0o022);
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_file(root.join("suid").as_ref(), b"x", 0o4600);
        make_dir(root.join("sgid").as_ref(), 0o2700);
        write_file(root.join("sticky").as_ref(), b"x", 0o1600);

        run(root, 0o022, &Options::default()).unwrap();

        assert_eq!(mode_of(root.join("suid").as_ref()), 0o4644);
        assert_eq!(mode_of(root.join("sgid").as_ref()), 0o2755);
        assert_eq!(mode_of(root.join("sticky").as_ref()), 0o1644);
    }

    #[test]
    fn dry_run_changes_nothing() {
        let _m = mask(0o022);
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let f = write_file(root.join("a.txt").as_ref(), b"a", 0o600);

        let opts = Options { dry_run: true };
        let entries = run(root, 0o022, &opts).unwrap();

        assert_eq!(mode_of(f.as_ref()), 0o600, "dry-run must not chmod");
        let entry = entries.iter().find(|e| e.path == f).unwrap();
        assert_eq!(
            entry.action,
            Action::Changed {
                from: 0o600,
                to: 0o644
            }
        );
    }

    #[test]
    fn symlinks_are_neither_followed_nor_changed() {
        let _m = mask(0o022);
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let root = dir.path();

        let target_file = outside.path().join("out.txt");
        write_file(target_file.as_ref(), b"outside", 0o600);
        let target_dir = outside.path().join("d");
        make_dir(target_dir.as_ref(), 0o700);
        write_file(target_dir.join("in.txt").as_ref(), b"t", 0o600);

        std::os::unix::fs::symlink(&target_file, root.join("link-file")).unwrap();
        std::os::unix::fs::symlink(&target_dir, root.join("link-dir")).unwrap();
        std::os::unix::fs::symlink(root.join("nope"), root.join("broken")).unwrap();

        let entries = run(root, 0o022, &Options::default()).unwrap();
        let rep = report(&entries);

        assert_eq!(
            mode_of(target_file.as_ref()),
            0o600,
            "symlink target must not be changed"
        );
        assert_eq!(mode_of(target_dir.as_ref()), 0o700);
        assert_eq!(mode_of(target_dir.join("in.txt").as_ref()), 0o600);
        assert_eq!(rep.skipped, 3, "three symlinks skipped");
        assert_eq!(rep.errors, 0);
        for e in &entries {
            if let Action::Skipped { reason } = &e.action {
                assert_eq!(*reason, "symlink");
            }
        }
    }

    #[test]
    fn fifo_is_skipped_not_changed() {
        let _m = mask(0o022);
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let fifo = root.join("pipe");
        let cpath = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: `cpath` is NUL-terminated; `mknod` only reads it.
        let rc = unsafe { libc::mknod(cpath.as_ptr(), (libc::S_IFIFO | 0o600) as libc::mode_t, 0) };
        if rc != 0 {
            eprintln!(
                "skipping: mknod failed: {}",
                std::io::Error::last_os_error()
            );
            return;
        }

        let entries = run(root, 0o022, &Options::default()).unwrap();

        assert_eq!(mode_of(fifo.as_ref()), 0o600, "fifo must not be chmodded");
        assert!(
            entries
                .iter()
                .any(|e| e.path == fifo && matches!(&e.action, Action::Skipped { .. }))
        );
    }

    #[test]
    fn missing_root_is_error() {
        let _m = mask(0o022);
        let err = run(
            Path::new("/definitely/not/here/permx"),
            0o022,
            &Options::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("cannot access"));
    }

    #[test]
    fn single_file_root() {
        let _m = mask(0o022);
        let dir = tempfile::tempdir().unwrap();
        let f = write_file(dir.path().join("f").as_ref(), b"x", 0o600);

        let entries = run(f.as_ref(), 0o022, &Options::default()).unwrap();

        assert_eq!(mode_of(f.as_ref()), 0o644);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].action,
            Action::Changed {
                from: 0o600,
                to: 0o644
            }
        );
    }

    #[test]
    fn root_symlink_is_followed() {
        let _m = mask(0o022);
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let real = outside.path();
        write_file(real.join("f").as_ref(), b"x", 0o600);
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(real, &link).unwrap();

        run(link.as_ref(), 0o022, &Options::default()).unwrap();

        assert_eq!(
            mode_of(real.join("f").as_ref()),
            0o644,
            "target file through a symlink root must be fixed"
        );
    }

    #[test]
    fn unreadable_file_records_error_but_is_still_fixed() {
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping: running as root, mode 0000 is still readable");
            return;
        }
        let _m = mask(0o022);
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let f = write_file(root.join("secret").as_ref(), b"s", 0o600);
        std::fs::set_permissions(f.as_path(), std::fs::Permissions::from_mode(0o0)).unwrap();

        let entries = run(root, 0o022, &Options::default()).unwrap();
        let rep = report(&entries);

        assert_eq!(rep.errors, 1, "detect() read failure must be recorded");
        assert_eq!(mode_of(f.as_ref()), 0o644, "chmod still applies");
    }
}
