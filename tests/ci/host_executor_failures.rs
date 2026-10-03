//! Infrastructure failures never become behavioural kills, even with a failed assertion.

use crate::harness::{execution_fixture, host_fixture, refused, succeeds};
use serde_json::{Value, json};
use std::fs;

#[test]
fn host_build_setup_zero_selection_timeout_and_cleanup_failures_are_distinct() {
    for (mode, expected) in [
        ("build", "build-failed"),
        ("provision", "provision-failed"),
        ("zero", "zero-or-incomplete-tests"),
        ("timeout", "timeout"),
        ("oom", "oom-or-signal"),
        ("cleanup", "cleanup-failed"),
        ("unknown", "invalid-receipt"),
        ("stale", "stale-artifacts"),
        ("source", "source-changed"),
        ("artifact", "invalid-artifacts"),
        ("baseline-bootstrap", "invalid-artifacts"),
        ("binding", "invalid-receipt"),
        ("incomplete", "incomplete"),
    ] {
        let mut fixture = execution_fixture(false);
        fixture.set("HOST_FIXTURE_MODE", mode);
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
        for outcome in result["outcomes"].as_array().unwrap() {
            assert_eq!(outcome["outcome"], expected, "{mode}: {outcome}");
        }
        assert_eq!(result["baseline_after"]["test"], "passed");
        assert!(!fixture.root.join("host-executor/scratch").exists());
    }
}

#[test]
fn internal_host_execution_refuses_missing_or_tampered_preparation() {
    let fixture = host_fixture();
    refused(
        &fixture.run_body("rust-gate mutants-host-execute"),
        "internal host execution requires gate-prepared state",
    );
    let fixture = execution_fixture(false);
    succeeds(&fixture.run_body("rust-gate mutants-plan"));
    succeeds(&fixture.run_body("rust-gate mutants-host"));
    let path = fixture.root.join("host-executor/prepared.json");
    let original: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    for field in [
        "plan_sha256",
        "scope_sha256",
        "provisioner_sha256",
        "sha",
        "attempt",
    ] {
        let mut altered = original.clone();
        altered[field] = json!("wrong");
        fs::write(&path, altered.to_string()).unwrap();
        refused(
            &fixture.run_body("rust-gate mutants-host-execute"),
            "host prepared-state digest or identity differs from preparation",
        );
    }
    fs::write(path, original.to_string()).unwrap();
}

#[test]
fn whole_executor_timeout_retains_logs_and_runs_independent_idempotent_cleanup() {
    let mut fixture = execution_fixture(false);
    fixture.set("HOST_FIXTURE_MODE", "hang");
    succeeds(&fixture.run_body("rust-gate mutants-plan"));
    fixture.stub(
        "timeout",
        r#"if [[ "$*" == *mutants-host-execute* ]]; then
exec /usr/bin/timeout --kill-after=1s 3s "${@:3}"
fi
exec /usr/bin/timeout "$@""#,
    );
    refused(
        &fixture.run_body("rust-gate mutants-host"),
        "host partition contains a survivor or non-behavioural failure",
    );
    let result: Value = serde_json::from_slice(
        &fs::read(
            fixture
                .root
                .join("reports/host-artifacts/host-interruption.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(result["outcome"], "timeout");
    assert_eq!(result["untested"].as_array().unwrap().len(), 2);
    assert!(
        fixture
            .root
            .join("reports/host-artifacts/baseline-before/request.json")
            .is_file()
    );
    assert!(
        fs::read_to_string(fixture.root.join("trace"))
            .unwrap()
            .contains("timeout --kill-after=1m 30m")
    );
    succeeds(&fixture.run_body("rust-gate mutants-host-cleanup"));
    succeeds(&fixture.run_body("rust-gate mutants-host-cleanup"));
    let cleanup: Value = serde_json::from_slice(
        &fs::read(
            fixture
                .root
                .join("reports/host-artifacts/cleanup/result.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(cleanup["removed"], json!([]));
}

#[test]
fn independent_cleanup_refuses_failed_receipts_and_resources_outside_its_scope() {
    for (mode, message) in [
        (
            "cleanup-outside",
            "host cleanup receipt escapes or omits its owned scope",
        ),
        (
            "cleanup-fail",
            "host independent cleanup failed or is missing",
        ),
    ] {
        let mut fixture = execution_fixture(false);
        succeeds(&fixture.run_body("rust-gate mutants-plan"));
        succeeds(&fixture.run_body("rust-gate mutants-host"));
        fixture.set("HOST_FIXTURE_MODE", mode);
        refused(&fixture.run_body("rust-gate mutants-host-cleanup"), message);
    }
}

#[test]
fn source_restoration_failure_is_reported_without_skipping_owned_cleanup() {
    let fixture = execution_fixture(false);
    succeeds(&fixture.run_body("rust-gate mutants-plan"));
    fixture.stub(
        "git",
        r#"if [[ "$*" == 'diff --name-only HEAD' ]]; then
printf 'src/host.rs\n'; exit 0
fi
exec /usr/bin/git "$@""#,
    );
    refused(
        &fixture.run_body("rust-gate mutants-host"),
        "host source restoration did not recover the baseline",
    );
    assert!(!fixture.root.join("host-executor/scratch").exists());
}

#[test]
fn failed_baseline_never_selects_a_weaker_mutant_provisioning_path() {
    let mut fixture = execution_fixture(false);
    fixture.set("HOST_FIXTURE_MODE", "baseline");
    succeeds(&fixture.run_body("rust-gate mutants-plan"));
    refused(
        &fixture.run_body("rust-gate mutants-host"),
        "host baseline failed; no mutant was provisioned",
    );
    assert!(
        !fixture
            .root
            .join("reports/host-artifacts/mutant-0")
            .exists()
    );
    assert!(
        fixture
            .root
            .join("reports/host-artifacts/baseline-after/result.json")
            .is_file()
    );
    let result: Value = serde_json::from_slice(
        &fs::read(
            fixture
                .root
                .join("reports/host-artifacts/host-interruption.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(result["untested"].as_array().unwrap().len(), 2);
    assert!(!fixture.root.join("host-executor/scratch").exists());
}

#[test]
fn final_baseline_failure_blocks_an_otherwise_completely_caught_population() {
    let mut fixture = execution_fixture(false);
    fixture.set("HOST_FIXTURE_MODE", "after");
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
    assert_eq!(result["baseline_after"]["provision"], "failed");
    assert!(
        result["outcomes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["outcome"] == "caught")
    );
    assert!(!fixture.root.join("host-executor/scratch").exists());
}
