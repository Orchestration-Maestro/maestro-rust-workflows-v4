//! `rust-gate msrv`: every workspace member must declare `rust-version`, the
//! declaration must be reachable by the compiler under test, and the workspace
//! must actually compile with the oldest compiler those declarations allow. A
//! workspace that never declares it still compiles today and then breaks for a
//! consumer on an older compiler with no warning; one that declares a version
//! nobody compiles against makes the same promise and keeps it by accident.

use crate::checks::cargo_metadata::ensure_metadata;
use crate::checks::rust_versions::parse;
use crate::runner::{Cmd, Job, Outcome, Step, input};
use std::fs;
use std::path::Path;

/// What this step declares: its inputs, its tools and its reports.
pub(crate) const STEPS: &[Step] = &[Step {
    workflow: "ci",
    id: "msrv",
    summary: "Declared minimum supported Rust version",
    inputs: &["RUSTUP_TOOLCHAIN"],
    tools: &["cargo check", "cargo metadata", "jaq", "rustup"],
    reports: &["msrv.tsv"],
    run,
}];

/// Package name and declared `rust-version`, empty when undeclared.
const DECLARATIONS: &str =
    ".workspace_members as $m | .packages[] | select(.id as $i | $m | index($i)) |
  [.name, (.rust_version // \"\")] | @tsv";

/// Run the step.
fn run() -> Outcome {
    let job = Job::current()?;
    let table = Cmd::new("jaq -er")
        .arg(DECLARATIONS)
        .arg(ensure_metadata(&job)?)
        .capture()?;
    let toolchain = input("RUSTUP_TOOLCHAIN")?;
    let selected = parse(&toolchain, false);
    for line in table.lines() {
        let (name, declared) = line.split_once('\t').unwrap_or((line, ""));
        if declared.is_empty() {
            return Err(format!("Package {name} must declare rust-version (its MSRV)").into());
        }
        let Some(msrv) = parse(declared, true).filter(|(major, _, _)| *major == 1) else {
            return Err(
                format!("Package {name} declares an unusable rust-version: {declared}").into(),
            );
        };
        if Some(msrv) > selected {
            return Err(format!(
                "Package {name} declares rust-version {declared}, above the selected {toolchain}"
            )
            .into());
        }
    }
    let report = job.report("msrv.tsv")?;
    fs::write(&report, &table)
        .map_err(|error| format!("cannot write {}: {error}", report.display()))?;
    compiles_at_its_floor(&table, &job.project)
}

/// The workspace must build with the oldest compiler its declarations allow.
/// Cargo refuses a member whose `rust-version` is above the active toolchain,
/// so that floor is the highest version declared: below it the build fails for
/// Cargo's own reason rather than the consumer's code. A member declaring less
/// is carried by the floor and is not checked on its own, which the run says
/// rather than leaves to be assumed.
fn compiles_at_its_floor(table: &str, project: &Path) -> Outcome {
    let declared: Vec<_> = table
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .filter_map(|(_, version)| parse(version, true))
        .collect();
    let Some(&(major, minor, patch)) = declared.iter().max() else {
        return Ok(());
    };
    // Rustup treats 1.85 as the latest patch; Cargo's declaration means 1.85.0.
    let floor = format!("{major}.{minor}.{patch}");
    if declared
        .iter()
        .any(|&version| version != (major, minor, patch))
    {
        println!(
            "REPORT: the workspace is checked at {floor}; a member declaring less is \
             carried by that floor, never compiled on its own"
        );
    }
    Cmd::new("rustup toolchain install")
        .arg(&floor)
        .args(["--profile", "minimal"])
        .cwd(project)
        .run()?;
    Cmd::new("cargo check --workspace --locked")
        .env("RUSTUP_TOOLCHAIN", &floor)
        .cwd(project)
        .run()
}
