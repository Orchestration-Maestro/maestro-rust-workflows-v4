//! Workflow environment and execution budgets keep consumer jobs isolated.

use crate::harness::{Fixture, root, step, workflow};
use std::fs;
use std::iter;
use std::os::unix::fs::symlink;

#[test]
fn every_consumer_job_has_an_explicit_build_target_policy() {
    let data = workflow("ci");
    for (id, job) in data["jobs"].as_object().unwrap() {
        let steps = job["steps"].as_array().unwrap();
        let _policy = match id.as_str() {
            "release" => {
                for command in ["tools", "build", "hardening", "stage"] {
                    let step = steps
                        .iter()
                        .find(|step| step["run"] == format!("rust-gate {command}"))
                        .unwrap();
                    assert_eq!(
                        step["env"]["CARGO_TARGET_DIR"], "${{ runner.temp }}/rust-target",
                        "{id}/{command} must use the step-local runner-temp target"
                    );
                }
                "step-local runner-temp target"
            }
            "checks"
            | "mutation-plan"
            | "mutations"
            | "mutation-engine"
            | "mutation-engine-default" => {
                // validate exports CARGO_TARGET_DIR from RUNNER_TEMP through GITHUB_ENV.
                assert!(
                    steps.iter().any(|step| step["run"] == "rust-gate validate"
                        && step.get("if").is_none()),
                    "{id} must obtain its target through unconditional validate"
                );
                "target exported through validate"
            }
            // Bare Cargo on native runners has no gate validate/environment export step.
            "portability" => "checkout-local Cargo default",
            "mutation-windows" | "mutation-host" => "disposable mutation trees",
            "mutation-summary" | "upload" | "coverage" | "gate" => {
                "evidence aggregation and uploads do not build consumer code"
            }
            _ => panic!("classify the build-target policy of new job {id}"),
        };
    }
}

#[test]
fn required_checks_budget_covers_cold_native_engine_builds() {
    assert_eq!(workflow("ci")["jobs"]["checks"]["timeout-minutes"], 240);
}

#[test]
fn release_steps_share_the_validated_consumer_build_environment() {
    let data = workflow("ci");
    let job = &data["jobs"]["release"];
    assert_eq!(
        job["env"]["PROJECT"],
        "${{ github.workspace }}/${{ needs.mutation-plan.outputs.directory }}"
    );
    for command in ["tools", "build", "hardening", "stage"] {
        let step = job["steps"]
            .as_array()
            .unwrap()
            .iter()
            .find(|step| step["run"] == format!("rust-gate {command}"))
            .unwrap();
        assert_eq!(
            step["env"],
            serde_json::json!({
                "REPORTS": "${{ runner.temp }}/rust-reports",
                "CARGO_TARGET_DIR": "${{ runner.temp }}/rust-target",
                "RUSTUP_TOOLCHAIN": "${{ needs.mutation-plan.outputs.toolchain }}",
                "CARGO_BUILD_TARGET": "x86_64-unknown-linux-gnu"
            }),
            "{command}"
        );
    }
    let upload = job["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["name"] == "Upload release diagnostic reports")
        .unwrap();
    assert_eq!(upload["with"]["path"], "${{ runner.temp }}/rust-reports/");
}

#[test]
fn workflows_never_override_github_or_runner_default_environment() {
    let mut violations = Vec::new();
    for entry in fs::read_dir(root().join(".github/workflows")).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_stem().unwrap().to_str().unwrap();
        let data = workflow(name);
        let jobs = data["jobs"].as_object().unwrap();
        let items = iter::once(&data).chain(jobs.values()).chain(
            jobs.values()
                .flat_map(|job| job["steps"].as_array().into_iter().flatten()),
        );
        violations.extend(
            items
                .flat_map(|item| {
                    item["env"]
                        .as_object()
                        .into_iter()
                        .flat_map(|env| env.keys())
                })
                .filter(|key| key.starts_with("GITHUB_") || key.starts_with("RUNNER_"))
                .map(|key| format!("{name}: {key}")),
        );
    }
    assert!(
        violations.is_empty(),
        "reserved workflow env: {violations:?}"
    );
}

#[test]
fn all_jobs_use_github_runners_without_caller_overrides() {
    for name in [
        "ci",
        "publish-binaries",
        "publish-crate",
        "ci-internal",
        "gate-mutation",
        "attest-binaries",
        "publish-evidence",
        "unsafe-audit",
        "fuzz",
        "dependabot-auto-merge",
    ] {
        let data = workflow(name);
        for input in ["runs-on", "publish-runs-on"] {
            assert!(
                data["on"]["workflow_call"]["inputs"].get(input).is_none(),
                "{name} allows a runner override: {input}"
            );
        }
        for (id, job) in data["jobs"].as_object().unwrap() {
            // The portability matrix and Windows mutation job use pinned
            // platform runners; every other job stays on Ubuntu.
            if name == "ci" && id == "portability" {
                assert_eq!(job["runs-on"], "${{ matrix.runner }}");
                assert_eq!(job["needs"], serde_json::json!(["mutation-plan"]));
                assert!(!job.to_string().contains("needs.checks"));
            } else if name == "ci" && id == "mutation-windows" {
                assert_eq!(job["runs-on"], "windows-2025");
            } else if job.get("steps").is_some() {
                assert_eq!(job["runs-on"], "ubuntu-24.04", "{name}/{id}");
            }
            if let Some(runner) = job["with"].get("runs-on") {
                assert_eq!(runner, "ubuntu-24.04", "{name}/{id}");
            }
        }
    }
}

#[test]
fn the_path_guard_is_identical_in_every_workflow_that_takes_a_directory() {
    // A reusable workflow runs inside the consumer's checkout, so the three
    // workflows that take a working directory used to embed the same Bash
    // guard three times. The gate holds it once, and running each validate
    // step against the same bad directories has to produce the same refusal,
    // word for word: not a simple path, a traversal, a symlink out of the
    // checkout, a directory that is not there.
    let cases = [
        ("../escape", "simple relative path"),
        ("project/../escape", "traverse or contain option-like"),
        ("project/out", "escapes checkout"),
        ("project/none", "does not exist inside checkout"),
    ];
    let mut refusals: Vec<Vec<String>> = Vec::new();
    for (workflow, command) in [
        ("ci", "rust-gate validate"),
        ("fuzz", "rust-gate fuzz validate"),
        ("unsafe-audit", "rust-gate unsafe-audit validate"),
    ] {
        assert_eq!(step(workflow, "validate").trim(), command);
        let mut seen = Vec::new();
        for (directory, refusal) in cases {
            let mut fixture = Fixture::new();
            if directory == "project/out" {
                symlink("/", fixture.root.join("project/out")).unwrap();
            }
            fixture.set("DIRECTORY", directory);
            let output = fixture.run(workflow, "validate");
            assert!(!output.status.success(), "{workflow} accepted {directory}");
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            assert!(
                stderr.contains(refusal),
                "{workflow} refused {directory} for another reason: {stderr}"
            );
            seen.push(stderr);
        }
        refusals.push(seen);
    }
    assert!(
        refusals.iter().all(|seen| seen == &refusals[0]),
        "the three workflows refuse the same directory differently: {refusals:?}"
    );
}
