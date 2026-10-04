//! Portability: a caller names extra platforms, the gate turns them into a
//! matrix of pinned runners, and the required status holds the run to them.

use crate::harness::{Fixture, refused, succeeds, workflow};
use serde_json::json;
use std::fs;

fn outputs(fixture: &Fixture) -> String {
    fs::read_to_string(fixture.root.join("output")).unwrap_or_default()
}

#[test]
fn named_platforms_become_a_matrix_of_pinned_runners() {
    let mut fixture = Fixture::new();
    fixture.set("PLATFORMS", "macos windows linux-arm");
    succeeds(&fixture.run("ci", "validate"));
    let written = outputs(&fixture);
    assert!(
        written
            .lines()
            .any(|line| line == r#"platforms=["macos-15","windows-2025","ubuntu-24.04-arm"]"#),
        "{written}"
    );
    assert!(written.lines().any(|line| line == "toolchain=1.98.1"));

    // Nothing named, nothing to run: the portability job is skipped.
    let none = Fixture::new();
    succeeds(&none.run("ci", "validate"));
    assert!(outputs(&none).lines().any(|line| line == "platforms="));

    // Refused before any output, like every other input.
    for (value, message) in [
        (
            "freebsd",
            "platforms may name only macos, windows and linux-arm",
        ),
        ("macos macos", "platforms names macos twice"),
        ("macos\nINJECT=1", "platforms may name only"),
    ] {
        let mut bad = Fixture::new();
        bad.set("PLATFORMS", value);
        refused(&bad.run("ci", "validate"), message);
        assert!(!bad.root.join("output").exists(), "{value:?}");
    }
}

#[test]
fn requested_platforms_must_pass_for_the_required_status() {
    let mut fixture = Fixture::new();
    for (key, value) in [
        ("MUTATION_TEST", "false"),
        ("MUTATION_MODE", "disabled"),
        ("MUTATION_COUNT", "0"),
        ("MUTATION_SHARDS", "0"),
        ("MUTATION_MATRIX", "[]"),
        ("MUTATIONS_RESULT", "skipped"),
        ("MUTATION_SUMMARY_RESULT", "skipped"),
        ("MUTATION_ATTEMPT", "1"),
    ] {
        fixture.set(key, value);
    }
    fixture.set("RESULT", "success");
    fixture.set("RUNNERS", r#"["macos-15"]"#);
    for status in ["failure", "cancelled", "skipped", ""] {
        fixture.set("PORTABILITY", status);
        refused(
            &fixture.run("ci", "required"),
            "Portability checks failed or were skipped",
        );
    }
    fixture.set("PORTABILITY", "success");
    succeeds(&fixture.run("ci", "required"));
    // No platform named: the skipped job is what was asked for.
    fixture.set("RUNNERS", "");
    fixture.set("PORTABILITY", "skipped");
    succeeds(&fixture.run("ci", "required"));
}

#[test]
fn the_portability_job_tests_the_validated_project_on_each_runner() {
    let ci = workflow("ci");
    let job = &ci["jobs"]["portability"];
    // Planning validates the directory and toolchain before either job starts.
    assert_eq!(job["needs"], json!(["mutation-plan"]));
    assert_eq!(
        job["if"],
        "${{ needs.mutation-plan.outputs.platforms != '' }}"
    );
    assert_eq!(
        job["strategy"]["matrix"]["runner"],
        "${{ fromJSON(needs.mutation-plan.outputs.platforms) }}"
    );
    assert_eq!(job["timeout-minutes"], 45);
    assert_eq!(job["strategy"]["fail-fast"], false);
    assert_eq!(job["runs-on"], "${{ matrix.runner }}");
    assert_eq!(job["permissions"], json!({"contents": "read"}));
    assert_eq!(
        job["env"]["RUSTUP_TOOLCHAIN"],
        "${{ needs.mutation-plan.outputs.toolchain }}"
    );
    // A job's own run defaults replace the workflow's, so the job names Bash
    // again: Windows would otherwise run the bodies in PowerShell, where
    // "$RUSTUP_TOOLCHAIN" is not the environment variable.
    assert_eq!(
        job["defaults"]["run"],
        json!({
            "shell": "bash",
            "working-directory": "${{ needs.mutation-plan.outputs.directory }}"
        })
    );
    let steps = job["steps"].as_array().unwrap();
    assert_eq!(
        steps[0]["uses"],
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
    );
    assert_eq!(steps[0]["with"]["persist-credentials"], false);
    let bodies: Vec<&str> = steps[1..]
        .iter()
        .map(|step| step["run"].as_str().unwrap().trim())
        .collect();
    assert_eq!(
        bodies,
        [
            r#"rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal"#,
            "cargo test --locked --workspace"
        ]
    );
}

#[test]
fn planning_hands_validated_outputs_to_portability_without_changing_required_status() {
    let ci = workflow("ci");
    let job = &ci["jobs"]["portability"];
    assert_eq!(
        job.to_string()
            .matches("needs.mutation-plan.outputs.")
            .count(),
        4
    );
    let steps = job["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 3);
    assert_eq!(steps[0]["with"]["ref"], "${{ github.sha }}");
    let plan = &ci["jobs"]["mutation-plan"]["outputs"];
    assert_eq!(plan["platforms"], "${{ steps.validate.outputs.platforms }}");
    assert_eq!(plan["toolchain"], "${{ steps.validate.outputs.toolchain }}");
    assert_eq!(plan["directory"], "${{ steps.validate.outputs.directory }}");
    let gate = &ci["jobs"]["gate"];
    assert_eq!(
        gate["needs"],
        json!([
            "mutation-plan",
            "checks",
            "portability",
            "mutations",
            "mutation-summary",
            "mutation-windows",
            "mutation-host",
            "mutation-engine",
            "mutation-engine-default"
        ])
    );
    let required = gate["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["id"] == "required")
        .unwrap();
    assert_eq!(
        required["env"]["PORTABILITY"],
        "${{ needs.portability.result }}"
    );
    assert_eq!(
        required["env"]["RUNNERS"],
        "${{ needs.checks.outputs.platforms }}"
    );
    assert_eq!(
        required["env"]["MUTATIONS_RESULT"],
        "${{ needs.mutations.result }}"
    );
    assert_eq!(
        required["env"]["MUTATION_SUMMARY_RESULT"],
        "${{ needs.mutation-summary.result }}"
    );
}

#[test]
fn the_consumer_matrix_proves_every_platform_and_requires_it() {
    // One consumer case names every platform, so each pinned runner builds
    // and tests a real fixture on every pull request here, and the required
    // consumer status waits for it.
    let internal = workflow("ci-internal");
    let case = &internal["jobs"]["portability-ci"];
    assert_eq!(case["uses"], "./.github/workflows/ci.yml");
    assert_eq!(case["with"]["platforms"], "macos windows linux-arm");
    let required = &internal["jobs"]["required"];
    assert!(
        required["needs"]
            .as_array()
            .unwrap()
            .contains(&json!("portability-ci"))
    );
    assert_eq!(
        required["steps"][0]["env"]["PORTABILITY_RESULT"],
        "${{ needs.portability-ci.result }}"
    );
}
