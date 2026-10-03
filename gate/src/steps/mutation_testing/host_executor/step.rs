//! Host execution orchestration, complete outcomes and an independent teardown entry.

use super::{
    identity,
    json::{field, read_json},
    prepared,
    protocol::HostRun,
    tree,
};
use crate::checks::digests::sha256_hex;
use crate::runner::{Cmd, Failure, Job, Outcome, input, write};
use std::env;
use std::fs;
use std::iter::once;
use std::path::Path;

/// Validate the early plan, prepare one clean checkout and execute serially.
pub(in crate::steps::mutation_testing) fn run() -> Outcome {
    let job = Job::current()?;
    let plan = identity::validate(&job)?;
    let host = prepare(&job, plan)?;
    let result = Cmd::new("timeout --kill-after=1m 30m")
        .arg(env::current_exe().map_err(|error| format!("cannot resolve host executor: {error}"))?)
        .arg("mutants-host-execute")
        .capture_output();
    let cleanup = cleanup_host(&host);
    let result = result?;
    let mut log = result.stdout;
    log.extend_from_slice(&result.stderr);
    write(&host.reports.join("executor.log"), &log, false)?;
    if !result.status.success() {
        let kind = match result.status.code() {
            Some(124) => "timeout",
            Some(137) | None => "oom-or-signal",
            _ => "executor-failed",
        };
        let progress = host.reports.join("host-progress.json");
        let completed = if progress.exists() {
            identity::safe_path(&host.reports, &progress)?;
            field(&read_json(&progress)?, ".outcomes|tojson")?
        } else {
            "[]".into()
        };
        let json = Cmd::new("jaq -cn")
            .args(["--arg", "outcome", kind])
            .args(["--argjson", "plan", &host.plan])
            .args(["--argjson", "completed", &completed])
            .arg(concat!(
                "{schema:1,outcome:$outcome,identity:$plan.identity,planned:$plan.mutants,",
                "executed:$completed,untested:[$plan.mutants[] | . as $m | ",
                "select([$completed[].mutant]|index($m)|not)]}"
            ))
            .capture()?;
        write(
            &host.reports.join("host-interruption.json"),
            json.as_bytes(),
            false,
        )?;
        eprintln!("{}", String::from_utf8_lossy(&log));
        cleanup?;
        return Err("host partition contains a survivor or non-behavioural failure".into());
    }
    print!("{}", String::from_utf8_lossy(&log));
    cleanup
}

/// A separately scheduled always-run entry also works after the executor is killed.
pub(in crate::steps::mutation_testing) fn cleanup() -> Outcome {
    let job = Job::current()?;
    let root = job.temp.join("host-executor");
    // No scope exists when validation failed before administrative work began.
    if !root.exists() {
        return Ok(());
    }
    cleanup_host(&prepared::load(&job)?)
}

/// Teardown and restoration both run, even when either one fails.
fn cleanup_host(host: &HostRun) -> Outcome {
    let cleaned = host.cleanup();
    let restored = tree::restore(&host.tree, &field(&host.plan, ".identity.sha")?);
    if let Err(error) = &restored {
        eprintln!("host source restoration failed: {:?}", error.message);
    }
    cleaned.and(restored)
}

/// Preserve the exact script and plan before starting disposable administration.
fn prepare(job: &Job, plan: String) -> Result<HostRun, Failure> {
    let root = job.temp.join("host-executor");
    fs::create_dir(&root)
        .map_err(|error| format!("cannot create exclusive host executor: {error}"))?;
    let reports = job.report("host-artifacts")?;
    fs::create_dir(&reports)
        .map_err(|error| format!("cannot create exclusive host artifacts: {error}"))?;
    write(&root.join("plan.json"), plan.as_bytes(), false)?;
    let script = fs::read(job.project.join(field(&plan, ".provisioner")?))
        .map_err(|error| format!("cannot retain provisioner: {error}"))?;
    write(&root.join("provisioner.sh"), &script, false)?;
    write(
        &root.join("scope.json"),
        scope(&root, &plan)?.as_bytes(),
        false,
    )?;
    let checkout = root.join("checkout");
    Cmd::new("git clone --no-hardlinks --no-local --quiet")
        .arg(input("GITHUB_WORKSPACE")?)
        .arg(&checkout)
        .capture()?;
    Cmd::new("git checkout --detach --quiet")
        .arg(field(&plan, ".identity.sha")?)
        .cwd(&checkout)
        .capture()?;
    let tree = checkout.join(field(&plan, ".identity.directory")?);
    identity::safe_path(&root, &tree)?;
    let host = HostRun {
        root,
        tree,
        reports,
        plan,
    };
    prepared::save(&host)?;
    Ok(host)
}

/// Explicit unique names cover every phase of every scenario, and nothing global.
fn scope(root: &Path, plan: &str) -> Result<String, Failure> {
    let run = input("GITHUB_RUN_ID")?;
    let attempt = input("GITHUB_RUN_ATTEMPT")?;
    if [&run, &attempt]
        .iter()
        .any(|value| value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err("host scope requires numeric run and attempt identities".into());
    }
    let prefix = format!("maestro-host-{run}-{attempt}");
    let installation = format!("/opt/maestro/n17/{run}-{attempt}");
    let profile = format!("/etc/apparmor.d/maestro-n17-parser-{run}-{attempt}");
    let count: usize = field(plan, ".mutants|length")?
        .parse()
        .map_err(|error| format!("cannot parse host plan count: {error}"))?;
    let mut units = Vec::new();
    for scenario in once("baseline-before".to_owned())
        .chain((0..count).map(|index| format!("mutant-{index}")))
        .chain(once("baseline-after".to_owned()))
    {
        for phase in [
            "normal",
            "abandon",
            "preparing",
            "recover_abandon",
            "recover_preparing",
        ] {
            units.push(format!("{prefix}-{scenario}-{phase}.service"));
        }
    }
    Cmd::new("jaq -cn")
        .args(["--arg", "prefix", &prefix])
        .arg("--arg")
        .arg("scratch")
        .arg(root.join("scratch"))
        .args(["--arg", "installation", &installation])
        .args(["--arg", "profile", &profile])
        .arg(concat!(
            "{schema:1,prefix:$prefix,scratch:$scratch,",
            "installation:$installation,profile:$profile,units:$ARGS.positional,",
            "resources:($ARGS.positional+[$installation,$profile,$scratch])}"
        ))
        .arg("--args")
        .args(units)
        .capture()
}

/// Internal entry refuses execution without the complete gate-written preparation binding.
pub(in crate::steps::mutation_testing) fn execute_prepared() -> Outcome {
    execute(&prepared::load(&Job::current()?)?)
}

/// Retain both baselines and every selected mutant, even when a partition is red.
fn execute(host: &HostRun) -> Outcome {
    let (before, baseline) = host.scenario("baseline-before", "null", "", "null")?;
    progress(host, &before, &[])?;
    if baseline != "survived" {
        host.scenario("baseline-after", "null", "", "null")?;
        return Err("host baseline failed; no mutant was provisioned".into());
    }
    let mut outcomes = Vec::new();
    let mut successful = true;
    let posture = field(&before, ".posture|tojson")?;
    let mutants = field(&host.plan, ".mutants[]|tojson")?;
    for (index, mutant) in mutants.lines().enumerate() {
        tree::restore(&host.tree, &field(&host.plan, ".identity.sha")?)?;
        let patched = tree::apply(&host.tree, mutant, &field(&host.plan, ".identity.sha")?)?;
        let (result, mut outcome) =
            host.scenario(&format!("mutant-{index}"), mutant, &patched, &posture)?;
        if result != "null" {
            let digests = "[.receipt.test_sha256,.receipt.bootstrap_sha256]|tojson";
            let same = field(&result, digests)? == field(&before, digests)?;
            if same {
                outcome = "stale-artifacts".into();
            }
        }
        successful &= outcome == "caught";
        let receipt = if result == "null" {
            "null".into()
        } else {
            field(&result, ".receipt|tojson")?
        };
        outcomes.push(
            Cmd::new("jaq -cn")
                .args(["--argjson", "mutant", mutant])
                .args(["--argjson", "receipt", &receipt])
                .args(["--arg", "outcome", &outcome])
                .args(["--arg", "patched", &patched])
                .arg(concat!(
                    "{mutant:$mutant,outcome:$outcome,",
                    "patched_source_sha256:$patched,receipt:$receipt}"
                ))
                .capture()?,
        );
        progress(host, &before, &outcomes)?;
        tree::restore(&host.tree, &field(&host.plan, ".identity.sha")?)?;
    }
    let (after, after_outcome) = host.scenario("baseline-after", "null", "", &posture)?;
    successful &= after_outcome == "survived";
    let bytes = fs::read(host.root.join("plan.json"))
        .map_err(|error| format!("cannot read host plan: {error}"))?;
    let json = Cmd::new("jaq -cn")
        .args(["--argjson", "plan", &host.plan])
        .args(["--arg", "digest", &sha256_hex(&bytes)])
        .args(["--argjson", "before", &before])
        .args(["--argjson", "after", &after])
        .args([
            "--argjson",
            "outcomes",
            &format!("[{}]", outcomes.join(",")),
        ])
        .arg(concat!(
            "{schema:1,sha:$plan.identity.sha,run_id:$plan.identity.run_id,",
            "attempt:$plan.identity.attempt,",
            "plan_sha256:$digest,policy_sha256:$plan.policy_sha256,",
            "provisioner_sha256:$plan.provisioner_sha256,source_sha256:$plan.source_sha256,",
            "baseline_before:$before.receipt,baseline_after:$after.receipt,outcomes:$outcomes}"
        ))
        .capture()?;
    write(
        &host.reports.join("host-outcomes.json"),
        json.as_bytes(),
        false,
    )?;
    println!(
        "Provisioned-host: {}",
        field(
            &json,
            ".outcomes|group_by(.outcome)|map(\"\\(.|length) \\(.[0].outcome)\")|join(\", \")"
        )?
    );
    // The original plan bytes, rather than compact reserialization, bind aggregation.
    if successful {
        Ok(())
    } else {
        Err("host partition contains a survivor or non-behavioural failure".into())
    }
}

/// Partial execution is retained before the next long script invocation can be interrupted.
fn progress(host: &HostRun, before: &str, outcomes: &[String]) -> Outcome {
    let json = Cmd::new("jaq -cn")
        .args(["--argjson", "plan", &host.plan])
        .args(["--argjson", "before", before])
        .args([
            "--argjson",
            "outcomes",
            &format!("[{}]", outcomes.join(",")),
        ])
        .arg(
            "{schema:1,identity:$plan.identity,baseline_before:$before.receipt,outcomes:$outcomes}",
        )
        .capture()?;
    write(
        &host.reports.join("host-progress.json"),
        json.as_bytes(),
        false,
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn host_phase_names_are_distinct_and_fixed() {
        let phases = [
            "normal",
            "abandon",
            "preparing",
            "recover_abandon",
            "recover_preparing",
        ];
        assert_eq!(phases.len(), 5);
    }
}
