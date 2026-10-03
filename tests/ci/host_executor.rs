//! Actual host protocol commands, exact patches and fail-closed execution.

use crate::harness::{
    Fixture, copy_tree, execution_fixture, fixture_git, host_fixture, output, refused, succeeds,
    workflow,
};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::{
    collections::BTreeMap,
    env, fs,
    mem::{self, ManuallyDrop},
};

#[test]
fn host_executor_refuses_identity_before_running_any_provisioner() {
    let mut fixture = host_fixture();
    succeeds(&fixture.run_body("rust-gate mutants-plan"));
    fixture.set(
        "MUTATION_HOST_PLAN",
        &fixture
            .root
            .join("reports/mutation-host-plan.json")
            .display()
            .to_string(),
    );
    fixture.set("WORKFLOW_REVISION", "");
    fixture.set("GITHUB_RUN_ATTEMPT", "2");
    refused(
        &fixture.run_body("rust-gate mutants-host"),
        "host executor identity, policy or source differs from its plan",
    );
    assert!(!fixture.calls().contains("--gate-host-v1"));
}

#[test]
fn host_execution_and_cleanup_are_independent_of_coverage_success() {
    let ci = workflow("ci");
    let host = &ci["jobs"]["mutation-host"];
    assert_eq!(host["needs"], serde_json::json!(["mutation-plan"]));
    assert_eq!(host["runs-on"], "ubuntu-24.04");
    assert_eq!(host["timeout-minutes"], 60);
    assert!(
        host["if"]
            .as_str()
            .unwrap()
            .contains("head.repo.full_name == github.repository")
    );
    let steps = host["steps"].as_array().unwrap();
    let execute = steps
        .iter()
        .find(|step| step["id"] == "host-execute")
        .unwrap();
    let cleanup = steps
        .iter()
        .find(|step| step["id"] == "host-cleanup")
        .unwrap();
    assert_eq!(execute["timeout-minutes"], 35);
    assert_eq!(cleanup["if"], "${{ always() }}");
    assert_eq!(cleanup["timeout-minutes"], 5);
    assert!(31 < execute["timeout-minutes"].as_u64().unwrap());
    assert!(
        execute["timeout-minutes"].as_u64().unwrap() < host["timeout-minutes"].as_u64().unwrap()
    );
    assert!(
        ci["jobs"]["mutation-summary"]["needs"]
            .as_array()
            .unwrap()
            .contains(&Value::from("mutation-host"))
    );
    // Evidence must survive both a survivor and an interrupted executor.
    assert_eq!(steps.last().unwrap()["if"], "${{ always() }}");
    assert_eq!(host["permissions"]["contents"], "read");
}

#[test]
fn host_executor_applies_exact_discovered_mutations_and_restores_both_baselines() {
    let mut fixture = execution_fixture(false);
    fixture.set("GITHUB_BASE_REF", "main");
    fixture.set("PULL_REQUEST_TITLE", "feat(ci): host executor");
    succeeds(&fixture.run_body("rust-gate mutants-plan"));
    let execution = fixture.run_body("rust-gate mutants-host");
    if !execution.status.success() {
        println!(
            "baseline: {}",
            fs::read_to_string(
                fixture
                    .root
                    .join("reports/host-artifacts/baseline-before/build.log")
            )
            .unwrap()
        );
    }
    succeeds(&execution);
    assert_plan_anchored_source_commands(&fixture);
    let path = fixture
        .root
        .join("reports/host-artifacts/host-outcomes.json");
    let result: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let planned: Value = serde_json::from_slice(
        &fs::read(fixture.root.join("reports/mutation-host-plan.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(result["outcomes"].as_array().unwrap().len(), 2);
    for (actual, mutant) in result["outcomes"]
        .as_array()
        .unwrap()
        .iter()
        .zip(planned["mutants"].as_array().unwrap())
    {
        assert_eq!(&actual["mutant"], mutant);
        assert_eq!(actual["outcome"], "caught");
        assert_eq!(actual["receipt"]["phases"].as_object().unwrap().len(), 5);
    }
    assert_eq!(result["baseline_before"]["test"], "passed");
    assert_eq!(result["baseline_after"]["test"], "passed");
    assert_eq!(
        fixture_git(
            &fixture.root.join("host-executor/checkout"),
            &["diff", "HEAD"]
        ),
        ""
    );
    assert_eq!(
        fixture_git(&fixture.root.join("project"), &["diff", "HEAD"]),
        ""
    );
    succeeds(&fixture.run_body("rust-gate mutants-host-cleanup"));
    succeeds(&fixture.run_body("rust-gate mutants-host-cleanup"));
    assert!(!fixture.root.join("host-executor/scratch").exists());
    let lcov = format!(
        "SF:{}/src/host.rs\nDA:1,0\nDA:2,0\nend_of_record\n",
        fixture.root.join("project").display()
    );
    fs::write(fixture.root.join("reports/coverage.lcov"), lcov).unwrap();
    succeeds(&fixture.run_body("rust-gate changed-coverage"));
    let checks = fixture.root.join("checks");
    copy_tree(&fixture.root.join("reports"), &checks);
    let aggregate = fixture.root.join("aggregate");
    fs::create_dir(&aggregate).unwrap();
    fixture.set("REPORTS", &aggregate.display().to_string());
    fixture.set("MUTATION_HOST_COUNT", "2");
    fixture.set("HOST_MUTATIONS_RESULT", "success");
    fixture.set("CHECKS_RESULT", "success");
    fixture.set("MUTATION_MODE", "empty");
    fixture.set("MUTATION_PLAN_DIR", &checks.display().to_string());
    fixture.set(
        "MUTATION_HOST_ARTIFACTS",
        &fixture
            .root
            .join("reports/host-artifacts")
            .display()
            .to_string(),
    );
    succeeds(&fixture.run_body("rust-gate mutants-aggregate"));
    assert_eq!(output(&fixture, "changed-coverage-state"), "passed");
}

#[test]
fn host_executor_retains_survivors_and_failure_artifacts_without_credit() {
    let fixture = ManuallyDrop::new(execution_fixture(true));
    succeeds(&fixture.run_body("rust-gate mutants-plan"));
    refused(
        &fixture.run_body("rust-gate mutants-host"),
        "host partition contains a survivor or non-behavioural failure",
    );
    let result: Value = serde_json::from_slice(
        &fs::read(
            fixture
                .root
                .join("reports/host-artifacts/host-outcomes.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let kinds: Vec<_> = result["outcomes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["outcome"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["caught", "survived"]);
    assert!(
        fixture
            .root
            .join("reports/host-artifacts/mutant-1/normal.log")
            .is_file()
    );
    assert!(!fixture.root.join("host-executor/scratch").exists());
    if let Ok(path) = env::var("HOST_QUALIFICATION_REPORTS") {
        copy_tree(
            &fixture.root.join("reports/host-artifacts"),
            &Path::new(&path).join("caught-survivor/artifacts"),
        );
        println!("caught=1 survived=1 partition=failed cleanup=passed artifacts=retained");
        let mut sentinel = ManuallyDrop::new(execution_fixture(false));
        sentinel.set(
            "HOST_FIXTURE_MODE",
            if env::var("GITHUB_ACTIONS").as_deref() == Ok("true") {
                "install-stale"
            } else {
                "baseline-bootstrap"
            },
        );
        succeeds(&sentinel.run_body("rust-gate mutants-plan"));
        refused(
            &sentinel.run_body("rust-gate mutants-host"),
            "host partition contains a survivor or non-behavioural failure",
        );
        let result: Value = serde_json::from_slice(
            &fs::read(
                sentinel
                    .root
                    .join("reports/host-artifacts/host-outcomes.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(
            result["outcomes"]
                .as_array()
                .unwrap()
                .iter()
                .all(|row| row["outcome"] == "invalid-artifacts")
        );
        for row in result["outcomes"].as_array().unwrap() {
            assert_ne!(
                row["receipt"]["test_sha256"],
                result["baseline_before"]["test_sha256"]
            );
        }
        copy_tree(
            &sentinel.root.join("reports/host-artifacts"),
            &Path::new(&path).join("install-sentinel/artifacts"),
        );
        println!("baseline-bootstrap=refused parent-test-binary=changed partition=failed");
        mem::forget(ManuallyDrop::into_inner(sentinel));
        mem::forget(ManuallyDrop::into_inner(fixture));
    } else {
        drop(ManuallyDrop::into_inner(fixture));
    }
}

#[test]
fn hosted_fixture_cleanup_collects_each_retained_scope_independently() {
    let fixtures = qualification_fixtures();
    if env::var_os("HOST_QUALIFICATION_REPORTS").is_some() {
        assert!(!fixtures.is_empty());
    }
    for fixture in fixtures {
        succeeds(&fixture.run_body("rust-gate mutants-host-cleanup"));
        succeeds(&fixture.run_body("rust-gate mutants-host-cleanup"));
        let root = env::var("HOST_QUALIFICATION_REPORTS").unwrap();
        let label = if fixture.env["HOST_FIXTURE_INSTALL"] == "true" {
            let plan: Value = serde_json::from_slice(
                &fs::read(fixture.root.join("reports/mutation-host-plan.json")).unwrap(),
            )
            .unwrap();
            assert!(
                !Path::new(&format!(
                    "/opt/maestro/n17/{}-{}",
                    plan["identity"]["run_id"].as_str().unwrap(),
                    plan["identity"]["attempt"].as_str().unwrap()
                ))
                .exists()
            );
            "root-owned installation absent"
        } else {
            "ordinary scratch absent"
        };
        let directory = &fixture.env["HOST_FIXTURE_CASE"];
        copy_tree(
            &fixture.root.join("reports/host-artifacts"),
            &Path::new(&root).join(directory).join("artifacts"),
        );
        println!("independent-cleanup=passed repeated-cleanup=passed {label}");
    }
}

/// Retained scopes remain available to a separately scheduled always-run qualification step.
fn qualification_fixtures() -> Vec<Fixture> {
    let Ok(output) = env::var("HOST_QUALIFICATION_REPORTS") else {
        return Vec::new();
    };
    fs::read_dir(output)
        .unwrap()
        .filter_map(|entry| {
            let path = entry.unwrap().path().join("cleanup-env.json");
            if !path.is_file() {
                return None;
            }
            let env: BTreeMap<String, String> =
                serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
            Some(Fixture {
                root: PathBuf::from(&env["RUNNER_TEMP"]),
                env,
            })
        })
        .collect()
}

/// Every source comparison uses the plan revision, including patch containment.
fn assert_plan_anchored_source_commands(fixture: &Fixture) {
    let trace = fs::read_to_string(fixture.root.join("trace")).unwrap();
    let sha = &fixture.env["GITHUB_SHA"];
    assert!(trace.contains(&format!("git diff --binary {sha}")));
    assert!(trace.contains(&format!("git diff --name-only {sha}")));
    assert!(!trace.contains("git diff --binary HEAD"));
    assert!(!trace.contains("git diff --name-only HEAD"));
}
