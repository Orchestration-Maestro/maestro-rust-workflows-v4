//! Every independent host plan binding is checked before consumer administration.

use crate::harness::{fixture_git, host_fixture, refused, succeeds};
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::symlink;

#[test]
fn executor_rejects_wrong_sha_attempt_script_source_and_unknown_plan_fields() {
    let mut fixture = host_fixture();
    fixture.set("WORKFLOW_REVISION", "");
    succeeds(&fixture.run_body("rust-gate mutants-plan"));
    let path = fixture.root.join("reports/mutation-host-plan.json");
    fixture.set("MUTATION_HOST_PLAN", &path.display().to_string());
    let original: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    for (pointer, value) in [
        ("/identity/sha", json!("0".repeat(40))),
        ("/identity/attempt", json!("2")),
        ("/identity/config_sha256", json!("0".repeat(64))),
        ("/identity/directory", json!("other")),
        ("/identity/run_id", json!("456")),
        ("/identity/toolchain", json!("1.97.0")),
        ("/identity/cargo_mutants_version", json!("26.0.0")),
        ("/identity/mutant_count", json!(-1)),
        ("/identity/shard_count", json!(0.5)),
        ("/policy_sha256", json!("0".repeat(64))),
        ("/provisioner", json!("other.sh")),
        ("/packages", json!(["other"])),
        ("/workflow_revision", json!("wrong")),
        ("/mutants/0/name", json!("")),
        ("/mutants/0/package", json!("foreign")),
        ("/mutants/0/file", json!("src/foreign.rs")),
        ("/mutants/0/diff", json!("")),
        ("/mutants/0/function/span/start/line", json!(2)),
        ("/mutants/0/function/span/end/line", json!(0)),
        ("/mutants/0/function/function_name", json!("")),
        ("/provisioner_sha256", json!("0".repeat(64))),
        ("/source_sha256", json!({})),
        ("/files", json!(["src/lib.rs"])),
        ("/features", json!([])),
        ("/schema", json!(2)),
    ] {
        let mut altered = original.clone();
        *altered.pointer_mut(pointer).unwrap() = value;
        fs::write(&path, altered.to_string()).unwrap();
        refused(
            &fixture.run_body("rust-gate mutants-host"),
            "host executor identity, policy or source differs from its plan",
        );
        assert!(!fixture.root.join("host-executor").exists());
    }
    let mut duplicated = original.clone();
    duplicated["mutants"]
        .as_array_mut()
        .unwrap()
        .push(original["mutants"][0].clone());
    fs::write(&path, duplicated.to_string()).unwrap();
    refused(
        &fixture.run_body("rust-gate mutants-host"),
        "host executor identity, policy or source differs from its plan",
    );
    assert!(!fixture.root.join("host-executor").exists());
    let mut altered = original.clone();
    altered["unknown"] = json!(true);
    fs::write(&path, altered.to_string()).unwrap();
    refused(
        &fixture.run_body("rust-gate mutants-host"),
        "host executor identity, policy or source differs from its plan",
    );
    altered = original.clone();
    altered["identity"]["first_parent"] = json!("0".repeat(40));
    fs::write(&path, altered.to_string()).unwrap();
    refused(
        &fixture.run_body("rust-gate mutants-host"),
        "host executor first parent differs from its plan",
    );
    fs::write(&path, original.to_string()).unwrap();
    let project = fixture.root.join("project");
    fs::write(project.join("maestro-quality.toml"), "# No host policy.\n").unwrap();
    fixture_git(&project, &["add", "."]);
    fixture_git(
        &project,
        &[
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            "ordinary",
        ],
    );
    refused(
        &fixture.run_body("rust-gate mutants-host"),
        "host executor requires a tested-head policy",
    );
}

#[test]
fn host_plan_inputs_reject_escape_symlinks_and_unpinned_discovery() {
    let mut fixture = host_fixture();
    fixture.set("MUTATION_HOST_PLAN", "/etc/passwd");
    refused(
        &fixture.run_body("rust-gate mutants-host"),
        "host protocol path escapes its scope",
    );
    let path = fixture.root.join("linked.json");
    symlink("/etc/passwd", &path).unwrap();
    fixture.set("MUTATION_HOST_PLAN", &path.display().to_string());
    refused(
        &fixture.run_body("rust-gate mutants-host"),
        "host protocol path contains a symlink",
    );
    // The policy reader needs actual workspace metadata before discovery.
    fixture.stub(
        "cargo",
        r#"if [[ "$1" == metadata ]]; then
cat "$RUNNER_TEMP/host-metadata.json"
elif [[ "$*" == 'mutants --version' ]]; then
printf 'cargo-mutants 26.0.0\n';
else printf '[]\n'; fi"#,
    );
    refused(
        &fixture.run_body("rust-gate mutants-plan"),
        "host discovery requires pinned cargo-mutants 27.1.0",
    );
}

#[test]
fn scope_resource_names_refuse_nonnumeric_run_and_attempt_identities() {
    let mut fixture = host_fixture();
    fixture.set("WORKFLOW_REVISION", "");
    fixture.set("GITHUB_RUN_ID", "not-an-id");
    succeeds(&fixture.run_body("rust-gate mutants-plan"));
    fixture.set(
        "MUTATION_HOST_PLAN",
        &fixture
            .root
            .join("reports/mutation-host-plan.json")
            .display()
            .to_string(),
    );
    refused(
        &fixture.run_body("rust-gate mutants-host"),
        "host scope requires numeric run and attempt identities",
    );
}

#[test]
fn live_checkout_head_drift_refuses_before_host_administration() {
    let mut fixture = host_fixture();
    fixture.set("WORKFLOW_REVISION", "");
    succeeds(&fixture.run_body("rust-gate mutants-plan"));
    let path = fixture.root.join("reports/mutation-host-plan.json");
    fixture.set("MUTATION_HOST_PLAN", &path.display().to_string());
    let project = fixture.root.join("project");
    fixture_git(
        &project,
        &[
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--allow-empty",
            "--quiet",
            "-m",
            "live drift",
        ],
    );
    refused(
        &fixture.run_body("rust-gate mutants-host"),
        "host executor identity, policy or source differs from its plan",
    );
    assert!(!fixture.root.join("host-executor").exists());
}
