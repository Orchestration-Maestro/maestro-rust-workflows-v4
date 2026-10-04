//! Independent release execution and the final, fail-closed scorecard join.

use crate::harness::{Fixture, SCORECARD_OUTCOMES, refused, succeeds, workflow};
use serde_json::{Value, json};
use std::fs;

#[test]
fn release_starts_from_planning_and_owns_the_payload() {
    let ci = workflow("ci");
    let release = &ci["jobs"]["release"];
    assert_eq!(release["needs"], json!(["mutation-plan"]));
    assert_eq!(
        release["env"]["RUSTUP_TOOLCHAIN"],
        "${{ needs.mutation-plan.outputs.toolchain }}"
    );
    let steps = release["steps"].as_array().unwrap();
    let commands: Vec<&str> = steps
        .iter()
        .filter_map(|step| step["run"].as_str())
        .collect();
    assert!(commands.ends_with(&["rust-gate build", "rust-gate hardening", "rust-gate stage"]));
    for id in ["build", "hardening", "stage", "upload"] {
        assert!(
            !ci["jobs"]["checks"]["steps"]
                .as_array()
                .unwrap()
                .iter()
                .any(|step| step["id"] == id)
        );
    }
    let gate = &ci["jobs"]["gate"];
    assert!(
        gate["needs"]
            .as_array()
            .unwrap()
            .contains(&json!("release"))
    );
    assert_eq!(
        gate["outputs"]["artifact-id"],
        "${{ steps.required.outcome == 'success' && needs.release.outputs.artifact-id || '' }}"
    );
    assert_eq!(release["outputs"]["revision"], "${{ github.sha }}");
    for id in ["build", "hardening", "stage"] {
        assert_eq!(
            release["outputs"][format!("out-{id}")],
            format!("${{{{ steps.{id}.outcome }}}}")
        );
    }
    let required = gate["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["id"] == "required")
        .unwrap();
    assert_eq!(
        required["env"]["RELEASE_RESULT"],
        "${{ needs.release.result }}"
    );
    let upload = gate["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["id"] == "final-scorecard-upload")
        .unwrap();
    assert_eq!(
        upload["with"]["name"],
        "${{ needs.mutation-plan.outputs.artifact-name }}-final-scorecard"
    );
}

#[test]
fn required_release_rejects_every_unsuccessful_job_result() {
    let mut fixture = Fixture::new();
    for (key, value) in [
        ("RESULT", "success"),
        ("MUTATION_MODE", "disabled"),
        ("MUTATION_COUNT", "0"),
        ("MUTATION_SHARDS", "0"),
        ("MUTATION_MATRIX", "[]"),
        ("MUTATIONS_RESULT", "skipped"),
        ("MUTATION_SUMMARY_RESULT", "skipped"),
    ] {
        fixture.set(key, value);
    }
    succeeds(&fixture.run("ci", "required"));
    for status in ["failure", "cancelled", "skipped", "", "unknown"] {
        fixture.set("RELEASE_RESULT", status);
        refused(
            &fixture.run("ci", "required"),
            "Release checks failed or were skipped",
        );
    }
    fixture.set("RELEASE_RESULT", "success");
    for key in [
        "OUT_BUILD",
        "OUT_HARDENING",
        "OUT_STAGE",
        "FINAL_SCORECARD_RESULT",
    ] {
        for status in ["failure", "cancelled", "skipped", "", "unknown"] {
            fixture.set(key, status);
            refused(
                &fixture.run("ci", "required"),
                "Release checks failed or were skipped",
            );
        }
        fixture.set(key, "success");
    }
    succeeds(&fixture.run("ci", "required"));
}

#[test]
fn final_scorecard_replaces_each_release_row_without_false_green() {
    for (result, outcome, expected) in [
        ("success", "success", "passed"),
        ("success", "failure", "failed"),
        ("success", "cancelled", "failed"),
        ("success", "skipped", "failed"),
        ("success", "", "failed"),
        ("success", "unknown", "failed"),
        ("failure", "success", "failed"),
        ("cancelled", "success", "failed"),
        ("skipped", "success", "failed"),
        ("", "success", "failed"),
    ] {
        let mut fixture = Fixture::new();
        for key in SCORECARD_OUTCOMES {
            fixture.set(key, "success");
        }
        succeeds(&fixture.run("ci", "scorecard"));
        fixture.set("RELEASE_FINALIZE", "true");
        fixture.set("RELEASE_RESULT", result);
        for key in ["OUT_BUILD", "OUT_HARDENING", "OUT_STAGE"] {
            fixture.set(key, outcome);
        }
        succeeds(&fixture.run("ci", "scorecard-finalize"));
        let card: Value = serde_json::from_str(
            &fs::read_to_string(fixture.root.join("reports/scorecard.json")).unwrap(),
        )
        .unwrap();
        for control in [
            "release tests, auditable build, verified packages and SBOMs",
            "reproducibility and binary hardening",
            "packaging and SBOM",
        ] {
            let row = card["controls"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["control"] == control)
                .unwrap();
            assert_eq!(row["state"], expected, "{result}/{outcome}: {control}");
        }
    }
}

#[test]
fn final_release_rows_use_their_own_step_outcomes() {
    let controls = [
        (
            "OUT_BUILD",
            "release tests, auditable build, verified packages and SBOMs",
        ),
        ("OUT_HARDENING", "reproducibility and binary hardening"),
        ("OUT_STAGE", "packaging and SBOM"),
    ];
    for (failed_key, _) in controls {
        let mut fixture = Fixture::new();
        for key in SCORECARD_OUTCOMES {
            fixture.set(key, "success");
        }
        succeeds(&fixture.run("ci", "scorecard"));
        fixture.set("RELEASE_FINALIZE", "true");
        fixture.set(failed_key, "failure");
        succeeds(&fixture.run("ci", "scorecard-finalize"));
        let card: Value =
            serde_json::from_slice(&fs::read(fixture.root.join("reports/scorecard.json")).unwrap())
                .unwrap();
        for (key, control) in controls {
            let row = card["controls"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["control"] == control)
                .unwrap();
            assert_eq!(
                row["state"],
                if key == failed_key {
                    "failed"
                } else {
                    "passed"
                }
            );
        }
    }
}

#[test]
fn final_join_keeps_canonical_upload_inputs_and_release_binding() {
    let ci = workflow("ci");
    for job in ["upload", "coverage"] {
        let download = ci["jobs"][job]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .find(|step| step["name"] == "Download this run's reports")
            .unwrap();
        assert_eq!(
            download["with"]["name"],
            "${{ needs.checks.outputs.artifact-name }}-reports"
        );
        assert_eq!(download["with"]["path"], "reports");
    }
    let release = &ci["jobs"]["release"];
    let steps = release["steps"].as_array().unwrap();
    let consumer = steps
        .iter()
        .find(|step| step["name"] == "Checkout consumer revision")
        .unwrap();
    assert_eq!(consumer["with"]["ref"], "${{ github.sha }}");
    assert_eq!(consumer["with"]["persist-credentials"], false);
    assert_eq!(
        release["env"]["PROJECT"],
        "${{ github.workspace }}/${{ needs.mutation-plan.outputs.directory }}"
    );
    assert_eq!(
        release["env"]["CARGO_TARGET_DIR"],
        "${{ github.workspace }}/rust-target"
    );
    assert_eq!(
        release["env"]["REPORTS"],
        "${{ github.workspace }}/rust-reports"
    );
    let gate = ci["jobs"]["gate"]["steps"].as_array().unwrap();
    let finalize = gate
        .iter()
        .find(|step| step["id"] == "release-scorecard-finalize")
        .unwrap();
    for (key, value) in [
        ("OUT_BUILD", "out-build"),
        ("OUT_HARDENING", "out-hardening"),
        ("OUT_STAGE", "out-stage"),
    ] {
        assert_eq!(
            finalize["env"][key],
            format!("${{{{ needs.release.outputs.{value} }}}}")
        );
    }
}
