//! Independent release execution and the final, fail-closed scorecard join.

use crate::harness::{Fixture, SCORECARD_OUTCOMES, action, refused, root, succeeds, workflow};
use serde_json::{Value, json};
use std::fs;
use std::path::Path;

#[test]
fn release_starts_from_planning_and_owns_the_payload() {
    let ci = workflow("ci");
    let release = &ci["jobs"]["release"];
    assert_eq!(release["needs"], json!(["mutation-plan"]));
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
    for status in ["failure", "cancelled", "skipped", "not-run", "", "unknown"] {
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
        for status in ["failure", "cancelled", "skipped", "not-run", "", "unknown"] {
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
    for key in ["CARGO_TARGET_DIR", "REPORTS"] {
        assert!(release["env"].get(key).is_none(), "step-local {key}");
        for id in ["build", "hardening", "stage"] {
            let step = steps.iter().find(|step| step["id"] == id).unwrap();
            let directory = if key == "REPORTS" {
                "rust-reports"
            } else {
                "rust-target"
            };
            assert_eq!(
                step["env"][key],
                format!("${{{{ runner.temp }}}}/{directory}")
            );
        }
    }
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

#[test]
fn release_bootstrap_executes_without_consumer_target_or_compiler() {
    let ci = workflow("ci");
    let env = &ci["jobs"]["release"]["env"];
    let gate = action("gate");
    let body = gate["runs"]["steps"][0]["run"].as_str().unwrap();
    let mut failures = Vec::new();
    for consumer in ["1.98.1", "1.85"] {
        let mut fixture = Fixture::new();
        fixture.env.remove("RUSTUP_TOOLCHAIN");
        fixture.env.remove("CARGO_BUILD_TARGET");
        fixture.set("GATE", root().join("gate").to_str().unwrap());
        if env.get("RUSTUP_TOOLCHAIN").is_some() {
            fixture.set("RUSTUP_TOOLCHAIN", consumer);
        }
        if let Some(target) = env["CARGO_BUILD_TARGET"].as_str() {
            fixture.set("CARGO_BUILD_TARGET", target);
        }
        fixture.stub(
            "cargo",
            r#"
[ "${RUSTUP_TOOLCHAIN:-}" != 1.85 ] || {
  echo 'rust-gate requires Rust 1.88' >&2; exit 1;
}
while [ "$1" != --target-dir ]; do shift; done
shift
output="$1${CARGO_BUILD_TARGET:+/$CARGO_BUILD_TARGET}/release"
mkdir -p "$output"
printf '#!/bin/sh\nexit 0\n' > "$output/rust-gate"
"#,
        );
        let output = fixture.run_body(body);
        if !output.status.success() {
            failures.push(format!(
                "{consumer}: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
            continue;
        }
        let installed = fs::read_to_string(fixture.root.join("path")).unwrap();
        assert!(Path::new(installed.trim()).join("rust-gate").is_file());
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn final_join_refuses_missing_duplicate_or_misclassified_release_controls() {
    for control in [
        "release tests, auditable build, verified packages and SBOMs",
        "reproducibility and binary hardening",
        "packaging and SBOM",
    ] {
        for defect in ["missing", "duplicate", "misclassified"] {
            let mut fixture = Fixture::new();
            for key in SCORECARD_OUTCOMES {
                fixture.set(key, "success");
            }
            succeeds(&fixture.run("ci", "scorecard"));
            let path = fixture.root.join("reports/scorecard.json");
            let mut card: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            let rows = card["controls"].as_array_mut().unwrap();
            let index = rows
                .iter()
                .position(|row| row["control"] == control)
                .unwrap();
            match defect {
                "missing" => {
                    rows.remove(index);
                }
                "duplicate" => rows.push(rows[index].clone()),
                _ => rows[index]["kind"] = json!("optional"),
            }
            fs::write(&path, serde_json::to_vec(&card).unwrap()).unwrap();
            fixture.set("RELEASE_FINALIZE", "true");
            refused(
                &fixture.run("ci", "scorecard-finalize"),
                "scorecard release controls must appear exactly once and be enforced",
            );
        }
    }
}

#[test]
fn final_join_fails_remaining_not_run_without_changing_preliminary_states() {
    let mut fixture = Fixture::new();
    for key in SCORECARD_OUTCOMES {
        fixture.set(key, "skipped");
    }
    fixture.set("MUTATION_TEST", "true");
    succeeds(&fixture.run("ci", "scorecard"));
    fixture.set("MUTATION_STATE", "not-run");
    succeeds(&fixture.run("ci", "scorecard-finalize"));
    let path = fixture.root.join("reports/scorecard.json");
    let before: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert!(
        before["controls"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["state"] == "not-run")
    );
    fixture.set("RELEASE_FINALIZE", "true");
    succeeds(&fixture.run("ci", "scorecard-finalize"));
    let after: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    for row in before["controls"].as_array().unwrap() {
        let final_row = after["controls"]
            .as_array()
            .unwrap()
            .iter()
            .find(|candidate| candidate["control"] == row["control"])
            .unwrap();
        if row["state"] == "not-run" {
            assert_eq!(final_row["state"], "failed", "{}", row["control"]);
        }
    }
    assert!(
        !after["controls"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["state"] == "not-run")
    );
}

#[test]
fn consumer_release_settings_apply_only_after_the_gate_bootstrap() {
    let ci = workflow("ci");
    let steps = ci["jobs"]["release"]["steps"].as_array().unwrap();
    let bootstrap = steps
        .iter()
        .position(|step| step["id"] == "release-gate-build")
        .unwrap();
    for command in [
        "rust-gate tools",
        "rust-gate build",
        "rust-gate hardening",
        "rust-gate stage",
    ] {
        let index = steps
            .iter()
            .position(|step| step["run"] == command)
            .unwrap();
        assert!(index > bootstrap);
        assert_eq!(
            steps[index]["env"]["RUSTUP_TOOLCHAIN"],
            "${{ needs.mutation-plan.outputs.toolchain }}"
        );
        assert_eq!(
            steps[index]["env"]["CARGO_BUILD_TARGET"],
            "x86_64-unknown-linux-gnu"
        );
    }
}
