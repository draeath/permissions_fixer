//! `permissions_fixer`: normalize file permissions across one or more
//! paths (directory trees or single files) according to the current umask.
//!
//! Each path is anchored to its own filesystem (like `find -xdev` per start
//! point) and symlinks are never followed. Files become `0666 & !umask` and
//! directories `0777 & !umask`; executable programs (ELF, a.out, PE, or
//! Mach-O; shared objects do not count) and scripts with a shebang
//! additionally get execute permission in every class that has read.
//! Setuid, setgid, and sticky bits are preserved.
//!
//! Exit codes: 0 on success, 1 if any entry could not be processed,
//! 2 on usage errors.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;

use permissions_fixer::scan::{self, Action, Options};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Paths to fix: a directory (the whole tree) or a single file.
    /// A symlink root is followed. Each path is anchored to its own
    /// filesystem, like `find -xdev` per start point.
    #[arg(value_name = "PATH", required = true)]
    paths: Vec<PathBuf>,

    /// Report changes without applying them.
    #[arg(short = 'n', long)]
    dry_run: bool,

    /// Print every action, skip, and a summary at the end.
    #[arg(short = 'v', long)]
    verbose: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let umask = permissions_fixer::current_umask();
    let opts = Options {
        dry_run: cli.dry_run,
    };

    let roots: Vec<&Path> = cli.paths.iter().map(|p| p.as_path()).collect();
    let entries = scan::run(&roots, umask, &opts);
    let report = scan::report(&entries);

    let show_actions = cli.dry_run || cli.verbose;
    let mut out = std::io::stdout();
    for entry in &entries {
        match &entry.action {
            Action::Changed { from, to } => {
                if show_actions {
                    let _ = writeln!(
                        out,
                        "{}: {:04o} -> {:04o}{}",
                        entry.path.display(),
                        from,
                        to,
                        if cli.dry_run { " (dry-run)" } else { "" }
                    );
                }
            }
            Action::Unchanged { mode } => {
                if cli.verbose {
                    let _ = writeln!(out, "{}: ok ({mode:04o})", entry.path.display());
                }
            }
            Action::Skipped { reason } => {
                if cli.verbose {
                    let _ = writeln!(out, "{}: skipped ({reason})", entry.path.display());
                }
            }
            Action::Error { message } => {
                eprintln!(
                    "permissions_fixer: {}: error: {message}",
                    entry.path.display()
                );
            }
        }
    }
    if show_actions {
        let _ = writeln!(
            out,
            "summary: checked={} changed={} skipped={} errors={}",
            report.checked, report.changed, report.skipped, report.errors
        );
    }

    if report.errors == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
