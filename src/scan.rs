//! Tree walk and permission application.
//!
//! The walk is multithreaded: a pool of workers pulls directories from a
//! shared queue and processes them, so entries are recorded in completion
//! order, which is not deterministic. All roots share one pool; each queued
//! directory carries the device of the root its walk started from, so the
//! xdev boundary is anchored per root, like `find -xdev` per start point.

use std::collections::VecDeque;
use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

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

/// Walk `roots` and normalize permissions to umask-derived values.
///
/// Each root stays on the filesystem containing that root: directories on
/// other devices (mount points) are themselves processed but not descended
/// into, like `find -xdev` per start point. A root that is itself a symlink
/// *is* followed, so passing a link to a directory behaves like passing the
/// directory. Roots that cannot be accessed are recorded as
/// [`Action::Error`] entries, and the walk continues with the remaining
/// roots. Repeated or overlapping roots are processed once per occurrence.
///
/// All directory roots are walked by one pool of threads (one per available
/// processor); the order of the returned entries depends on scheduling and
/// is not deterministic.
pub fn run(roots: &[&Path], umask: u32, opts: &Options) -> Vec<Entry> {
    let mut entries = Vec::new();
    let mut seeds: Vec<(PathBuf, u64)> = Vec::new();
    for root in roots {
        match fs::metadata(root) {
            Ok(meta) => {
                entries.extend(process_entry(root, &meta, umask, opts));
                if meta.is_dir() {
                    seeds.push((root.to_path_buf(), meta.dev()));
                }
            }
            Err(err) => {
                entries.push(Entry {
                    path: root.to_path_buf(),
                    action: Action::Error {
                        message: format!("cannot access: {err}"),
                    },
                });
            }
        }
    }
    if !seeds.is_empty() {
        let nthreads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        entries.extend(walk_parallel(&seeds, umask, opts, nthreads));
    }
    entries
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

/// Compute and apply the permission change for one entry.
///
/// Returns one [`Entry`] normally, or two when the executable detection
/// fails: the [`Action::Error`] for the read failure plus the entry for the
/// permission change, which is still applied.
fn process_entry(path: &Path, meta: &fs::Metadata, umask: u32, opts: &Options) -> Vec<Entry> {
    let mut entries = Vec::new();
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
        return entries;
    }
    if opts.dry_run {
        entries.push(Entry {
            path: path.to_path_buf(),
            action: Action::Changed {
                from: current,
                to: desired,
            },
        });
        return entries;
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
    entries
}

/// How many directories a worker pulls from the queue per lock acquisition.
const QUEUE_BATCH: usize = 32;
/// How many subdirectories are buffered before being pushed to the shared
/// queue, so other workers see the work while a fan-out directory is still
/// being processed.
const PUSH_CHUNK: usize = 64;

/// Parallel walk over a set of top-level directories and their subtrees.
///
/// Each queue item is a directory plus the device of the root that walk
/// started from, so the xdev boundary is anchored per root, like
/// `find -xdev` per start point. `nthreads` workers pull batches of items
/// from a shared queue and process them (permission changes, special files,
/// mount points), enqueuing same-device subdirectories in chunks. Each
/// worker accumulates its own entry list, merged after join, so recording
/// entries never contends. A worker exits only when the queue is empty
/// *and* no worker holds a batch, so the walk always drains completely.
/// Order across directories is nondeterministic.
fn walk_parallel(
    dirs: &[(PathBuf, u64)],
    umask: u32,
    opts: &Options,
    nthreads: usize,
) -> Vec<Entry> {
    let nthreads = nthreads.max(1);
    let opts = *opts; // copied: the worker closures are 'static
    let queue: Arc<Mutex<VecDeque<(PathBuf, u64)>>> =
        Arc::new(Mutex::new(VecDeque::from(dirs.to_vec())));
    // Count of workers holding a non-empty batch; an empty queue plus zero
    // in-flight workers proves the walk is complete.
    let in_flight: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(nthreads);
    for _ in 0..nthreads {
        let queue = Arc::clone(&queue);
        let in_flight = Arc::clone(&in_flight);
        handles.push(std::thread::spawn(move || -> Vec<Entry> {
            let mut entries = Vec::new();
            let mut batch: Vec<(PathBuf, u64)> = Vec::with_capacity(QUEUE_BATCH);
            loop {
                // Take a whole batch under one lock acquisition, and count
                // the take while still holding it: a directory is either in
                // the queue or visible in `in_flight`, never in an uncounted
                // in-between state.
                batch.clear();
                {
                    let mut q = queue.lock().unwrap();
                    for _ in 0..QUEUE_BATCH {
                        match q.pop_front() {
                            Some(item) => batch.push(item),
                            None => break,
                        }
                    }
                    if !batch.is_empty() {
                        in_flight.fetch_add(1, Ordering::AcqRel);
                    }
                }
                if batch.is_empty() {
                    if in_flight.load(Ordering::Acquire) == 0 {
                        return entries;
                    }
                    std::thread::yield_now();
                    continue;
                }
                let guard = InFlight {
                    count: in_flight.clone(),
                };
                for (dir, dev) in &batch {
                    process_dir(dir, *dev, umask, &opts, &mut entries, &queue);
                }
                drop(guard);
            }
        }));
    }
    let mut all = Vec::new();
    for handle in handles {
        all.extend(handle.join().unwrap());
    }
    all
}

/// RAII decrement of the in-flight counter, so a panicking worker is still
/// counted down and the walk cannot deadlock on a leaked count.
struct InFlight {
    count: Arc<AtomicUsize>,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Process one directory: record an entry for each child, and enqueue
/// same-device subdirectories for further processing. `root_dev` is the
/// device of the root this walk started from: children stay anchored to
/// that same device.
fn process_dir(
    dir: &Path,
    root_dev: u64,
    umask: u32,
    opts: &Options,
    entries: &mut Vec<Entry>,
    queue: &Mutex<VecDeque<(PathBuf, u64)>>,
) {
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
    // Keep per-directory order deterministic; order across directories
    // depends on worker scheduling.
    let mut paths: Vec<PathBuf> = read_dir
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .collect();
    paths.sort();
    // Buffer subdirectory enqueues so a wide fan-out reaches the queue in
    // chunks instead of one lock acquisition per entry.
    let mut pending: Vec<(PathBuf, u64)> = Vec::new();
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
            entries.extend(process_entry(&path, &meta, umask, opts));
            if same_device(root_dev, meta.dev()) {
                pending.push((path, root_dev));
                if pending.len() >= PUSH_CHUNK {
                    queue.lock().unwrap().extend(std::mem::take(&mut pending));
                }
            } else {
                entries.push(Entry {
                    path: path.clone(),
                    action: Action::Skipped {
                        reason: "mount point; not descending",
                    },
                });
            }
        } else if meta.is_file() {
            entries.extend(process_entry(&path, &meta, umask, opts));
        } else {
            entries.push(Entry {
                path: path.clone(),
                action: Action::Skipped {
                    reason: describe(&meta.file_type()),
                },
            });
        }
    }
    if !pending.is_empty() {
        queue.lock().unwrap().extend(std::mem::take(&mut pending));
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
        let entries = run(&[root], 0o022, &opts);
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

        run(&[root], 0o022, &Options::default());

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

        run(&[root], 0o077, &Options::default());

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

        run(&[root], 0o022, &Options::default());

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
        let entries = run(&[root], 0o022, &opts);

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

        let entries = run(&[root], 0o022, &Options::default());
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

        let entries = run(&[root], 0o022, &Options::default());

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
        let missing = Path::new("/definitely/not/here/permx");
        let entries = run(&[missing], 0o022, &Options::default());

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, missing.to_path_buf());
        assert!(
            matches!(&entries[0].action, Action::Error { message } if message.contains("cannot access")),
            "action: {:?}",
            entries[0].action
        );
    }

    #[test]
    fn multiple_roots_continue_past_missing() {
        let _m = mask(0o022);
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let r1 = d1.path();
        let r2 = d2.path();
        // tempdir's own mode depends on mkdtemp/umask; make it explicit.
        std::fs::set_permissions(r1, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(r2, std::fs::Permissions::from_mode(0o700)).unwrap();
        write_file(r1.join("f1").as_ref(), b"1", 0o600);
        write_file(r2.join("f2").as_ref(), b"2", 0o600);
        make_dir(r2.join("d").as_ref(), 0o700);

        let missing = Path::new("/definitely/not/here/permx_missing");
        let entries = run(&[r1, missing, r2], 0o022, &Options::default());
        let rep = report(&entries);

        assert_eq!(mode_of(r1), 0o755);
        assert_eq!(mode_of(r1.join("f1").as_ref()), 0o644);
        assert_eq!(mode_of(r2), 0o755);
        assert_eq!(mode_of(r2.join("f2").as_ref()), 0o644);
        assert_eq!(mode_of(r2.join("d").as_ref()), 0o755);
        assert_eq!(rep.checked, 5);
        assert_eq!(rep.changed, 5);
        assert_eq!(rep.errors, 1);
        assert!(
            entries.iter().any(|e| e.path == missing.to_path_buf()
                && matches!(&e.action, Action::Error { message } if message.contains("cannot access"))),
            "entries: {entries:?}"
        );
    }

    #[test]
    fn mixed_file_and_directory_roots() {
        let _m = mask(0o022);
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        make_dir(root.join("d").as_ref(), 0o700);
        let f = write_file(root.join("f").as_ref(), b"x", 0o600);
        let d = root.join("d");

        let entries = run(&[f.as_ref(), d.as_ref()], 0o022, &Options::default());
        let rep = report(&entries);

        assert_eq!(mode_of(f.as_ref()), 0o644);
        assert_eq!(mode_of(d.as_ref()), 0o755);
        assert_eq!(rep.checked, 2);
        assert_eq!(rep.changed, 2);
        assert_eq!(rep.errors, 0);
    }

    #[test]
    fn single_file_root() {
        let _m = mask(0o022);
        let dir = tempfile::tempdir().unwrap();
        let f = write_file(dir.path().join("f").as_ref(), b"x", 0o600);

        let entries = run(&[f.as_ref()], 0o022, &Options::default());

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

        run(&[link.as_ref()], 0o022, &Options::default());

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

        let entries = run(&[root], 0o022, &Options::default());
        let rep = report(&entries);

        assert_eq!(rep.errors, 1, "detect() read failure must be recorded");
        assert_eq!(mode_of(f.as_ref()), 0o644, "chmod still applies");
    }

    /// `dirs` subdirectories, each with `files` files; dirs 0700, files 0600.
    fn build_tree(root: &Path, dirs: usize, files: usize) {
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
        for d in 0..dirs {
            let dir = root.join(format!("d{d}"));
            make_dir(&dir, 0o700);
            for f in 0..files {
                write_file(&dir.join(format!("f{f}")), b"x\n", 0o600);
            }
        }
    }

    #[test]
    fn parallel_walk_fixes_wide_tree() {
        let _m = mask(0o022);
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        build_tree(root, 120, 3);

        let entries = run(&[root], 0o022, &Options::default());
        let rep = report(&entries);

        let total = 120 * 3 + 120 + 1; // files + subdirs + root
        assert_eq!(rep.checked, total);
        assert_eq!(rep.changed, total);
        assert_eq!(rep.skipped, 0);
        assert_eq!(rep.errors, 0);
        assert_eq!(mode_of(root), 0o755);
        assert_eq!(mode_of(root.join("d0").as_ref()), 0o755);
        assert_eq!(mode_of(root.join("d0").join("f0").as_ref()), 0o644);
        assert_eq!(mode_of(root.join("d119").join("f2").as_ref()), 0o644);
    }

    #[test]
    fn parallel_walk_deep_chain() {
        let _m = mask(0o022);
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let depth = 400;
        let mut cur = root.to_path_buf();
        // tempdir's own mode depends on mkdtemp/umask; make the starting
        // state explicit.
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
        for i in 0..depth {
            cur = cur.join(format!("n{i}"));
            std::fs::create_dir(&cur).unwrap();
            std::fs::set_permissions(&cur, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        write_file(cur.join("leaf").as_ref(), b"l\n", 0o600);

        let entries = run(&[root], 0o022, &Options::default());
        let rep = report(&entries);

        assert_eq!(rep.checked, depth + 2); // root + chain + leaf
        assert_eq!(rep.changed, depth + 2);
        assert_eq!(rep.errors, 0);
        assert_eq!(mode_of(root), 0o755);
        assert_eq!(mode_of(cur.as_ref()), 0o755);
        assert_eq!(mode_of(cur.join("leaf").as_ref()), 0o644);
    }

    #[test]
    fn parallel_walk_single_thread() {
        let _m = mask(0o022);
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        build_tree(root, 8, 2);

        // walk_parallel covers the seeded directories, not their parents.
        let dev = std::fs::metadata(root).unwrap().dev();
        let entries = walk_parallel(&[(root.to_path_buf(), dev)], 0o022, &Options::default(), 1);
        let rep = report(&entries);

        assert_eq!(rep.checked, 8 * 2 + 8);
        assert_eq!(rep.changed, 8 * 2 + 8);
        assert_eq!(rep.errors, 0);
        assert_eq!(mode_of(root.join("d0").join("f1").as_ref()), 0o644);
        assert_eq!(mode_of(root.join("d7").as_ref()), 0o755);
    }
}
