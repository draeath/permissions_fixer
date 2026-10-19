//! End-to-end tests for the `permissions_fixer` binary.

mod common;

use std::os::unix::fs::PermissionsExt;

use common::{make_dir, mask, mode_of, run, write_file};
use permissions_fixer::exec::fixtures;

/// Build the standard fixture tree (see individual tests for expectations).
fn fixture() -> (tempfile::TempDir, tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();

    // tempdir's own mode depends on mkdtemp/umask; make it explicit.
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();

    make_dir(root.join("dir").as_ref(), 0o700);
    make_dir(root.join("dir").join("deep").as_ref(), 0o700);
    write_file(
        root.join("dir").join("deep").join("f").as_ref(),
        b"deep\n",
        0o600,
    );
    write_file(root.join("a.txt").as_ref(), b"hello\n", 0o600);
    write_file(root.join("ok.txt").as_ref(), b"ok\n", 0o644);
    write_file(
        root.join("script.sh").as_ref(),
        b"#!/bin/sh\necho hi\n",
        0o600,
    );
    write_file(
        root.join("prog").as_ref(),
        &fixtures::elf(3, 2, true, &[(1, 0), (3, 0)], None),
        0o600,
    );
    write_file(
        root.join("lib.so").as_ref(),
        &fixtures::elf(3, 2, true, &[(1, 0)], Some(&[0u8; 16])),
        0o600,
    );
    // Classic a.out (ZMAGIC): an executable program
    write_file(root.join("legacy").as_ref(), b"\x05\x00\x08\x01", 0o600);
    write_file(root.join("setuid").as_ref(), b"u\n", 0o4644);

    let outside_file = outside.path().join("out.txt");
    write_file(outside_file.as_ref(), b"outside\n", 0o600);
    std::os::unix::fs::symlink(&outside_file, root.join("link")).unwrap();

    (dir, outside, root)
}

fn root_arg(root: &std::path::Path) -> String {
    root.to_string_lossy().into_owned()
}

#[test]
fn usage_and_help() {
    let help = run(vec!["--help".into()]);
    assert!(help.status.success(), "stderr: {}", help.stderr);
    assert!(help.stdout.contains("dry-run"), "stdout: {}", help.stdout);
    assert!(help.stdout.contains("verbose"), "stdout: {}", help.stdout);
    // any number of paths is accepted
    assert!(help.stdout.contains("<PATH>..."), "stdout: {}", help.stdout);

    // CARGO_PKG_VERSION tracks Cargo.toml, so this stays in sync when the
    // package version is bumped.
    let version = run(vec!["--version".into()]);
    assert!(version.status.success());
    assert!(
        version.stdout.contains(env!("CARGO_PKG_VERSION")),
        "stdout: {}",
        version.stdout
    );

    let none = run(vec![]);
    assert_eq!(
        none.status.code(),
        Some(2),
        "missing argument is a usage error"
    );

    let bogus = run(vec!["--nope".into(), "/tmp".into()]);
    assert_eq!(
        bogus.status.code(),
        Some(2),
        "unknown flag is a usage error"
    );
}

#[test]
fn quiet_run_applies_modes_and_prints_nothing() {
    let _m = mask(0o022);
    let (dir, outside, root) = fixture();
    let res = run(vec![root_arg(&root)]);

    assert!(res.status.success(), "stderr: {}", res.stderr);
    assert!(
        res.stdout.is_empty(),
        "quiet prints nothing, got: {}",
        res.stdout
    );
    assert!(
        res.stderr.is_empty(),
        "no errors expected, got: {}",
        res.stderr
    );

    assert_eq!(mode_of(root.join("a.txt").as_ref()), 0o644);
    assert_eq!(mode_of(root.join("script.sh").as_ref()), 0o755);
    assert_eq!(mode_of(root.join("prog").as_ref()), 0o755);
    assert_eq!(mode_of(root.join("lib.so").as_ref()), 0o644);
    assert_eq!(mode_of(root.join("legacy").as_ref()), 0o755);
    assert_eq!(mode_of(root.join("setuid").as_ref()), 0o4644);
    assert_eq!(mode_of(root.join("dir").as_ref()), 0o755);
    assert_eq!(mode_of(root.join("dir").join("deep").as_ref()), 0o755);
    assert_eq!(
        mode_of(root.join("dir").join("deep").join("f").as_ref()),
        0o644
    );
    assert_eq!(
        mode_of(outside.path().join("out.txt").as_ref()),
        0o600,
        "symlink target must be untouched"
    );
    drop((dir, outside));
}

#[test]
fn dry_run_reports_but_changes_nothing() {
    let _m = mask(0o022);
    let (dir, _outside, root) = fixture();
    let res = run(vec!["-n".into(), root_arg(&root)]);

    assert!(res.status.success(), "stderr: {}", res.stderr);
    assert!(
        res.stdout.contains("a.txt: 0600 -> 0644 (dry-run)"),
        "stdout: {}",
        res.stdout
    );
    assert!(
        res.stdout.contains("script.sh: 0600 -> 0755 (dry-run)"),
        "stdout: {}",
        res.stdout
    );
    assert!(
        res.stdout.contains("lib.so: 0600 -> 0644 (dry-run)"),
        "stdout: {}",
        res.stdout
    );
    assert!(
        res.stdout.contains("legacy: 0600 -> 0755 (dry-run)"),
        "stdout: {}",
        res.stdout
    );
    assert!(
        res.stdout
            .contains("summary: checked=11 changed=9 skipped=1 errors=0"),
        "stdout: {}",
        res.stdout
    );

    // nothing was applied
    assert_eq!(mode_of(root.join("a.txt").as_ref()), 0o600);
    assert_eq!(mode_of(root.join("script.sh").as_ref()), 0o600);
    assert_eq!(mode_of(root.join("prog").as_ref()), 0o600);
    assert_eq!(mode_of(root.join("lib.so").as_ref()), 0o600);
    assert_eq!(mode_of(root.join("legacy").as_ref()), 0o600);
    drop((dir, _outside));
}

#[test]
fn verbose_reports_everything_then_idempotent() {
    let _m = mask(0o022);
    let (dir, _outside, root) = fixture();

    let first = run(vec!["-v".into(), root_arg(&root)]);
    assert!(first.status.success(), "stderr: {}", first.stderr);
    assert!(
        first.stdout.contains("a.txt: 0600 -> 0644"),
        "stdout: {}",
        first.stdout
    );
    assert!(
        first.stdout.contains("ok.txt: ok (0644)"),
        "stdout: {}",
        first.stdout
    );
    assert!(
        first.stdout.contains("setuid: ok (4644)"),
        "stdout: {}",
        first.stdout
    );
    assert!(
        first.stdout.contains("link: skipped (symlink)"),
        "stdout: {}",
        first.stdout
    );
    assert!(
        first
            .stdout
            .contains("summary: checked=11 changed=9 skipped=1 errors=0"),
        "stdout: {}",
        first.stdout
    );

    let second = run(vec!["-v".into(), root_arg(&root)]);
    assert!(second.status.success());
    assert!(
        !second.stdout.contains("->"),
        "second run changes nothing: {}",
        second.stdout
    );
    assert!(
        second
            .stdout
            .contains("summary: checked=11 changed=0 skipped=1 errors=0"),
        "stdout: {}",
        second.stdout
    );
    drop((dir, _outside));
}

/// Seed one standard tree under a root (dirs 0700, files 0600).
fn seed_tree(root: &std::path::Path) {
    // tempdir's own mode depends on mkdtemp/umask; make it explicit.
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
    make_dir(root.join("sub").as_ref(), 0o700);
    write_file(root.join("sub").join("deep.txt").as_ref(), b"deep\n", 0o600);
    write_file(root.join("note.txt").as_ref(), b"note\n", 0o600);
    write_file(root.join("script").as_ref(), b"#!/bin/sh\necho hi\n", 0o600);
}

#[test]
fn multiple_roots_fix_every_root() {
    let _m = mask(0o022);
    let d1 = tempfile::tempdir().unwrap();
    let d2 = tempfile::tempdir().unwrap();
    seed_tree(d1.path());
    seed_tree(d2.path());

    let res = run(vec![root_arg(d1.path()), root_arg(d2.path())]);

    assert!(res.status.success(), "stderr: {}", res.stderr);
    assert!(
        res.stdout.is_empty(),
        "quiet prints nothing, got: {}",
        res.stdout
    );
    assert!(
        res.stderr.is_empty(),
        "no errors expected, got: {}",
        res.stderr
    );

    for r in [d1.path(), d2.path()] {
        assert_eq!(mode_of(r), 0o755);
        assert_eq!(mode_of(r.join("sub").as_ref()), 0o755);
        assert_eq!(mode_of(r.join("sub").join("deep.txt").as_ref()), 0o644);
        assert_eq!(mode_of(r.join("note.txt").as_ref()), 0o644);
        assert_eq!(mode_of(r.join("script").as_ref()), 0o755);
    }
}

#[test]
fn multiple_roots_missing_one_still_processes_others() {
    let _m = mask(0o022);
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    seed_tree(root);

    let missing = "/definitely/not/here/permx_missing";
    let res = run(vec![missing.into(), root_arg(root)]);

    assert_eq!(res.status.code(), Some(1), "stderr: {}", res.stderr);
    assert!(
        res.stderr.contains("cannot access"),
        "stderr: {}",
        res.stderr
    );
    assert!(res.stderr.contains(missing), "stderr: {}", res.stderr);
    // the good root was still fully processed
    assert_eq!(mode_of(root), 0o755);
    assert_eq!(mode_of(root.join("sub").as_ref()), 0o755);
    assert_eq!(mode_of(root.join("note.txt").as_ref()), 0o644);
    assert_eq!(mode_of(root.join("script").as_ref()), 0o755);
}

#[test]
fn multiple_roots_dry_run_reports_all_and_changes_nothing() {
    let _m = mask(0o022);
    let d1 = tempfile::tempdir().unwrap();
    let d2 = tempfile::tempdir().unwrap();
    seed_tree(d1.path());
    seed_tree(d2.path());

    let res = run(vec!["-n".into(), root_arg(d1.path()), root_arg(d2.path())]);

    assert!(res.status.success(), "stderr: {}", res.stderr);
    for r in [d1.path(), d2.path()] {
        assert!(
            res.stdout.contains(&format!(
                "{}: 0600 -> 0644 (dry-run)",
                r.join("note.txt").display()
            )),
            "stdout: {}",
            res.stdout
        );
        assert!(
            res.stdout.contains(&format!(
                "{}: 0600 -> 0755 (dry-run)",
                r.join("script").display()
            )),
            "stdout: {}",
            res.stdout
        );
    }
    assert!(
        res.stdout
            .contains("summary: checked=10 changed=10 skipped=0 errors=0"),
        "stdout: {}",
        res.stdout
    );
    // nothing was applied
    assert_eq!(mode_of(d1.path()), 0o700);
    assert_eq!(mode_of(d1.path().join("note.txt").as_ref()), 0o600);
    assert_eq!(mode_of(d2.path().join("script").as_ref()), 0o600);
}

#[test]
fn mount_point_passed_as_its_own_root_is_descended() {
    let _m = mask(0o022);
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let sub = root.join("mnt");
    let outer = root.join("outer.txt");
    let inner = sub.join("inner.txt");
    let inner2 = sub.join("inner2.txt");
    let inner_mode = root.join("inner_mode.txt");
    let inner2_mode = root.join("inner2_mode.txt");
    let mnt_mode = root.join("mnt_mode.txt");
    let outer_mode = root.join("outer_mode.txt");
    let out1 = root.join("out1.txt");
    let err1 = root.join("err1.txt");
    let out2 = root.join("out2.txt");
    let err2 = root.join("err2.txt");
    make_dir(&sub, 0o700);
    write_file(&outer, b"outer\n", 0o600);

    let probe = std::process::Command::new("unshare")
        .args(["-r", "-m", "true"])
        .status();
    if !probe.map(|s| s.success()).unwrap_or(false) {
        eprintln!("skipping: unshare -r -m not available");
        return;
    }

    // Run 1: the mount point passed as its own root must be descended into,
    // even though it is a mount point *relative to the outer root*.
    // Run 2: one invocation with both the outer root and the mount-point
    // root must fix both sides of the mount boundary.
    let script = format!(
        "mount -t tmpfs tmpfs '{sub}' || exit 97\n\
         chmod 755 '{sub}'\n\
         printf 'inner\\n' > '{inner}'\n\
         chmod 600 '{inner}'\n\
         {bin} '{sub}' -v > '{out1}' 2> '{err1}'\n\
         rc1=$?\n\
         stat -c '%a' '{inner}' > '{inner_mode}'\n\
         printf 'inner2\\n' > '{inner2}'\n\
         chmod 600 '{inner2}'\n\
         {bin} '{root}' '{sub}' -v > '{out2}' 2> '{err2}'\n\
         rc2=$?\n\
         stat -c '%a' '{inner2}' > '{inner2_mode}'\n\
         stat -c '%a' '{sub}' > '{mnt_mode}'\n\
         stat -c '%a' '{outer}' > '{outer_mode}'\n\
         umount '{sub}' 2>/dev/null\n\
         if [ \"$rc1\" -ne 0 ]; then exit \"$rc1\"; fi\n\
         if [ \"$rc2\" -ne 0 ]; then exit \"$rc2\"; fi\n\
         exit 0\n",
        sub = sub.display(),
        inner = inner.display(),
        inner2 = inner2.display(),
        inner_mode = inner_mode.display(),
        inner2_mode = inner2_mode.display(),
        mnt_mode = mnt_mode.display(),
        outer_mode = outer_mode.display(),
        outer = outer.display(),
        out1 = out1.display(),
        err1 = err1.display(),
        out2 = out2.display(),
        err2 = err2.display(),
        bin = common::bin().display(),
        root = root.display(),
    );
    let st = std::process::Command::new("unshare")
        .args(["-r", "-m", "sh", "-c", &script])
        .status()
        .unwrap();
    assert!(st.success(), "mount/run script failed: {script}");

    assert_eq!(
        std::fs::read_to_string(&inner_mode).unwrap().trim(),
        "644",
        "file on the tmpfs must be fixed when the mount point is a root"
    );
    assert_eq!(
        std::fs::read_to_string(&inner2_mode).unwrap().trim(),
        "644",
        "file on the tmpfs must be fixed via the mount-point root in a combined run"
    );
    assert_eq!(
        std::fs::read_to_string(&mnt_mode).unwrap().trim(),
        "755",
        "the mount point itself is still chmodded"
    );
    assert_eq!(
        std::fs::read_to_string(&outer_mode).unwrap().trim(),
        "644",
        "file on the outer root's filesystem must be fixed"
    );
    let out1_txt = std::fs::read_to_string(&out1).unwrap();
    assert!(
        out1_txt.contains("inner.txt: 0600 -> 0644"),
        "verbose output of the mount-point root run: {out1_txt}"
    );
    let out2_txt = std::fs::read_to_string(&out2).unwrap();
    assert!(
        out2_txt.contains("inner2.txt: 0600 -> 0644"),
        "combined run must descend the mount point: {out2_txt}"
    );
    assert!(
        out2_txt.contains("skipped (mount point"),
        "combined run must note that the outer root does not cross the mount: {out2_txt}"
    );
}

#[test]
fn missing_root_is_an_error() {
    let res = run(vec!["/definitely/not/here/permx_test".into()]);
    assert_eq!(res.status.code(), Some(1));
    assert!(
        res.stderr.contains("cannot access"),
        "stderr: {}",
        res.stderr
    );
}

#[test]
fn errors_yield_exit_code_one() {
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipping: root ignores read permissions");
        return;
    }
    let _m = mask(0o022);
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_file(root.join("secret").as_ref(), b"s\n", 0o600);
    std::fs::set_permissions(
        root.join("secret").as_path(),
        std::fs::Permissions::from_mode(0o0),
    )
    .unwrap();

    let res = run(vec![root_arg(root)]);
    assert_eq!(res.status.code(), Some(1), "stderr: {}", res.stderr);
    assert!(res.stderr.contains("error"), "stderr: {}", res.stderr);
    // the chmod itself still applied
    assert_eq!(mode_of(root.join("secret").as_ref()), 0o644);
}

#[test]
fn does_not_cross_mount_points() {
    let _m = mask(0o022);
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let sub = root.join("mnt");
    let inner = sub.join("inner.txt");
    let inner_mode = root.join("inner_mode.txt");
    let outer = root.join("outer.txt");
    let out = root.join("verbose_out.txt");
    let err = root.join("verbose_err.txt");
    make_dir(&sub, 0o755);
    write_file(&outer, b"outer\n", 0o600);

    let probe = std::process::Command::new("unshare")
        .args(["-r", "-m", "true"])
        .status();
    if !probe.map(|s| s.success()).unwrap_or(false) {
        eprintln!("skipping: unshare -r -m not available");
        return;
    }

    let script = format!(
        "mount -t tmpfs tmpfs '{sub}' || exit 97\n\
         printf 'inner\\n' > '{inner}'\n\
         chmod 600 '{inner}'\n\
         {bin} '{root}' -v > '{out}' 2> '{err}'\n\
         rc=$?\n\
         stat -c '%a' '{inner}' > '{inner_mode}'\n\
         umount '{sub}' 2>/dev/null\n\
         exit $rc\n",
        sub = sub.display(),
        inner = inner.display(),
        bin = common::bin().display(),
        root = root.display(),
        out = out.display(),
        err = err.display(),
        inner_mode = inner_mode.display(),
    );
    let st = std::process::Command::new("unshare")
        .args(["-r", "-m", "sh", "-c", &script])
        .status()
        .unwrap();
    assert!(st.success(), "mount/run script failed: {script}");

    let inner_mode_txt = std::fs::read_to_string(&inner_mode).unwrap();
    assert_eq!(
        inner_mode_txt.trim(),
        "600",
        "file on the other filesystem must be untouched"
    );
    assert_eq!(
        mode_of(&outer),
        0o644,
        "file on the root filesystem must be fixed"
    );
    let out_txt = std::fs::read_to_string(&out).unwrap();
    assert!(
        out_txt.contains("skipped (mount point"),
        "verbose output should note the mount point: {out_txt}"
    );
}

#[test]
fn real_elf_binaries_from_cc() {
    let cc_probe = std::process::Command::new("cc").arg("--version").output();
    if !cc_probe.map(|o| o.status.success()).unwrap_or(false) {
        eprintln!("skipping: cc not available");
        return;
    }
    let _m = mask(0o022);
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    make_dir(root.join("binaries").as_ref(), 0o755);

    std::fs::write(root.join("main.c"), b"int main(void){return 42;}\n").unwrap();
    let prog = root.join("binaries/prog");
    let st = std::process::Command::new("cc")
        .args([
            "-o",
            prog.to_str().unwrap(),
            root.join("main.c").to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(st.success(), "cc failed to build the executable");

    // sanity check: what we just built really is a runnable program (while
    // it still carries its default exec permissions)
    let run_st = std::process::Command::new(&prog).status().unwrap();
    assert_eq!(run_st.code(), Some(42));
    std::fs::set_permissions(&prog, std::fs::Permissions::from_mode(0o600)).unwrap();

    std::fs::write(root.join("lib.c"), b"int foo(void){return 7;}\n").unwrap();
    let lib = root.join("binaries/libfoo.so");
    let st = std::process::Command::new("cc")
        .args([
            "-shared",
            "-fPIC",
            "-o",
            lib.to_str().unwrap(),
            root.join("lib.c").to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(st.success(), "cc failed to build the shared object");
    std::fs::set_permissions(&lib, std::fs::Permissions::from_mode(0o600)).unwrap();

    let res = run(vec![root_arg(root)]);
    assert!(res.status.success(), "stderr: {}", res.stderr);
    assert_eq!(
        mode_of(&prog),
        0o755,
        "a real executable must get the exec bit"
    );
    assert_eq!(
        mode_of(&lib),
        0o644,
        "a real shared object must not get the exec bit"
    );
}
