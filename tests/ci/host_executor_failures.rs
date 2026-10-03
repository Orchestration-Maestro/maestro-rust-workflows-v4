//! Infrastructure failures never become behavioural kills, even with a failed assertion.

use crate::harness::{
    execution_fixture, fixture_git, host_evidence_digest, host_fixture, refused, succeeds,
};
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::symlink;

#[test]
fn host_build_setup_zero_selection_timeout_and_cleanup_failures_are_distinct() {
    let mut fixture = execution_fixture(false);
    fixture.set("HOST_FIXTURE_WARM_CACHE", "true");
    succeeds(&fixture.run_body("rust-gate mutants-plan"));
    succeeds(&fixture.run_body("rust-gate mutants-host"));
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
        fixture.set("HOST_FIXTURE_MODE", mode);
        let reports = fixture.root.join("reports/host-artifacts");
        fs::remove_dir_all(&reports).unwrap();
        fs::create_dir(&reports).unwrap();
        refused(
            &fixture.run_body("rust-gate mutants-host-execute"),
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
        succeeds(&fixture.run_body("rust-gate mutants-host-cleanup"));
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
    let mut fixture = execution_fixture(false);
    succeeds(&fixture.run_body("rust-gate mutants-plan"));
    succeeds(&fixture.run_body("rust-gate mutants-host"));
    for (mode, message) in [
        (
            "cleanup-schema",
            "host cleanup receipt escapes or omits its owned scope",
        ),
        (
            "cleanup-binding",
            "host cleanup receipt escapes or omits its owned scope",
        ),
        (
            "cleanup-unknown",
            "host cleanup receipt escapes or omits its owned scope",
        ),
        (
            "cleanup-outside",
            "host cleanup receipt escapes or omits its owned scope",
        ),
        (
            "cleanup-fail",
            "host independent cleanup failed or is missing",
        ),
    ] {
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
        r#"if [[ "$*" == diff\ --name-only\ * ]]; then
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

#[test]
fn independent_cleanup_refuses_a_symlinked_request_without_overwriting_its_target() {
    let fixture = execution_fixture(false);
    succeeds(&fixture.run_body("rust-gate mutants-plan"));
    succeeds(&fixture.run_body("rust-gate mutants-host"));
    let request = fixture
        .root
        .join("reports/host-artifacts/cleanup/request.json");
    let sentinel = fixture.root.join("sentinel");
    fs::write(&sentinel, "outside sentinel").unwrap();
    fs::remove_file(&request).unwrap();
    symlink(&sentinel, &request).unwrap();
    refused(
        &fixture.run_body("rust-gate mutants-host-cleanup"),
        "host request is not a regular file",
    );
    assert_eq!(fs::read_to_string(sentinel).unwrap(), "outside sentinel");
    fs::remove_file(&request).unwrap();
    fs::create_dir(&request).unwrap();
    refused(
        &fixture.run_body("rust-gate mutants-host-cleanup"),
        "host request is not a regular file",
    );
}

#[test]
fn committed_baseline_source_changes_are_refused_and_restored_to_the_plan() {
    for mode in ["source-commit", "source-empty"] {
        let mut fixture = execution_fixture(false);
        fixture.set("HOST_FIXTURE_MODE", mode);
        succeeds(&fixture.run_body("rust-gate mutants-plan"));
        refused(
            &fixture.run_body("rust-gate mutants-host"),
            "host baseline failed; no mutant was provisioned",
        );
        let tree = fixture.root.join("host-executor/checkout");
        assert_eq!(
            fixture_git(&tree, &["rev-parse", "HEAD"]),
            fixture.env["GITHUB_SHA"]
        );
        assert_eq!(
            fs::read(tree.join("src/lib.rs")).unwrap(),
            fs::read(fixture.root.join("project/src/lib.rs")).unwrap()
        );
        assert!(
            !fixture
                .root
                .join("reports/host-artifacts/mutant-0")
                .exists()
        );
        assert!(!fixture.root.join("host-executor/scratch").exists());
        assert!(
            fs::read_to_string(fixture.root.join("reports/host-artifacts/executor.log"))
                .unwrap()
                .contains("source-changed")
        );
    }
}

#[test]
fn timeout_precedes_invalid_receipt_and_artifact_classifications() {
    let mut fixture = execution_fixture(false);
    fixture.set("HOST_FIXTURE_WARM_CACHE", "true");
    succeeds(&fixture.run_body("rust-gate mutants-plan"));
    succeeds(&fixture.run_body("rust-gate mutants-host"));
    for (mode, expected, diagnostic) in [
        ("timeout-invalid", "timeout", "invalid-receipt"),
        ("oom-invalid", "oom-or-signal", "invalid-receipt"),
        ("timeout-artifact", "timeout", "invalid-artifacts"),
        ("timeout-stale", "timeout", "invalid-artifacts"),
    ] {
        fixture.set("HOST_FIXTURE_MODE", mode);
        let output = fixture.run_body("rust-gate mutants-host-execute");
        refused(
            &output,
            "host partition contains a survivor or non-behavioural failure",
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains(diagnostic));
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
            assert_eq!(outcome["outcome"], expected);
        }
        succeeds(&fixture.run_body("rust-gate mutants-host-cleanup"));
    }
}

#[test]
fn independent_cleanup_refuses_symlinked_and_foreign_scratch_roots() {
    let fixture = execution_fixture(false);
    succeeds(&fixture.run_body("rust-gate mutants-plan"));
    succeeds(&fixture.run_body("rust-gate mutants-host"));
    let scratch = fixture.root.join("host-executor/scratch");
    let outside = fixture.root.join("foreign");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("sentinel"), "outside sentinel").unwrap();
    let scope = fixture.root.join("host-executor/scope.json");
    let digest = host_evidence_digest(&fixture, &scope.display().to_string());
    fs::write(outside.join(".gate-host-scope"), &digest).unwrap();
    symlink(&outside, &scratch).unwrap();
    refused(
        &fixture.run_body("rust-gate mutants-host-cleanup"),
        "host independent cleanup failed or is missing",
    );
    assert_eq!(
        fs::read_to_string(outside.join("sentinel")).unwrap(),
        "outside sentinel"
    );
    fs::remove_file(&scratch).unwrap();
    fs::create_dir(&scratch).unwrap();
    fs::write(scratch.join("sentinel"), "foreign scratch").unwrap();
    refused(
        &fixture.run_body("rust-gate mutants-host-cleanup"),
        "host independent cleanup failed or is missing",
    );
    assert_eq!(
        fs::read_to_string(scratch.join("sentinel")).unwrap(),
        "foreign scratch"
    );
    let marker = scratch.join(".gate-host-scope");
    symlink(outside.join(".gate-host-scope"), &marker).unwrap();
    refused(
        &fixture.run_body("rust-gate mutants-host-cleanup"),
        "host independent cleanup failed or is missing",
    );
    assert!(scratch.join("sentinel").exists());
    fs::remove_file(&marker).unwrap();
    fs::write(marker, digest).unwrap();
    fixture.stub(
        "stat",
        r#"if [[ "$*" == '-c %u '* ]]; then
printf '4294967294\n'; else exec /usr/bin/stat "$@"; fi"#,
    );
    refused(
        &fixture.run_body("rust-gate mutants-host-cleanup"),
        "host independent cleanup failed or is missing",
    );
    assert_eq!(
        fs::read_to_string(scratch.join("sentinel")).unwrap(),
        "foreign scratch"
    );
}

#[test]
fn cleanup_source_commits_are_refused_after_teardown_and_restored_to_the_plan() {
    let mut fixture = execution_fixture(false);
    succeeds(&fixture.run_body("rust-gate mutants-plan"));
    succeeds(&fixture.run_body("rust-gate mutants-host"));
    for mode in [
        "cleanup-commit",
        "cleanup-empty",
        "cleanup-source",
        "cleanup-reset",
    ] {
        if mode == "cleanup-reset" {
            fixture_git(
                &fixture.root.join("host-executor/checkout"),
                &[
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "--allow-empty",
                    "--quiet",
                    "-m",
                    "drift",
                ],
            );
        }
        fixture.set("HOST_FIXTURE_MODE", mode);
        refused(
            &fixture.run_body("rust-gate mutants-host-cleanup"),
            "host cleanup changed source or HEAD",
        );
        assert!(!fixture.root.join("host-executor/scratch").exists());
        let receipt: Value = serde_json::from_slice(
            &fs::read(
                fixture
                    .root
                    .join("reports/host-artifacts/cleanup/result.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(receipt["cleanup"], "passed");
        let tree = fixture.root.join("host-executor/checkout");
        assert_eq!(
            fixture_git(&tree, &["rev-parse", "HEAD"]),
            fixture.env["GITHUB_SHA"]
        );
        assert!(fixture_git(&tree, &["diff", "--binary", &fixture.env["GITHUB_SHA"]]).is_empty());
        assert_eq!(
            fs::read(tree.join("src/lib.rs")).unwrap(),
            fs::read(fixture.root.join("project/src/lib.rs")).unwrap()
        );
    }
}

#[test]
fn restoration_head_failure_retains_cleanup_result_and_reports_both_errors() {
    let fixture = execution_fixture(false);
    succeeds(&fixture.run_body("rust-gate mutants-plan"));
    succeeds(&fixture.run_body("rust-gate mutants-host"));
    let tree = fixture.root.join("host-executor/checkout");
    fixture_git(
        &tree,
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--allow-empty",
            "--quiet",
            "-m",
            "drift",
        ],
    );
    fixture.stub(
        "git",
        r#"if [[ "$*" == reset\ --hard\ * ]]; then exit 0; fi
exec /usr/bin/git "$@""#,
    );
    let output = fixture.run_body("rust-gate mutants-host-cleanup");
    refused(&output, "host cleanup changed source or HEAD");
    refused(
        &output,
        "host source restoration did not recover the baseline",
    );
    assert!(!fixture.root.join("host-executor/scratch").exists());
    assert!(
        fixture
            .root
            .join("reports/host-artifacts/cleanup/result.json")
            .is_file()
    );
    fixture_git(&tree, &["reset", "--hard", &fixture.env["GITHUB_SHA"]]);
}
