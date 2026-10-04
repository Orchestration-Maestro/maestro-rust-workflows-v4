//! Metadata readers work independently of the quality job's temporary files.

use crate::harness::{Fixture, succeeds};
use serde_json::json;
use std::fs;

/// One workspace and deterministic external producers, without cached metadata.
fn fresh_workspace() -> Fixture {
    let mut fixture = Fixture::new();
    let target = fixture.root.join("target");
    fs::create_dir(&target).unwrap();
    fixture.set("CARGO_TARGET_DIR", &target.display().to_string());
    fixture.set(
        "METADATA",
        &json!({"workspace_members": ["fixture"], "packages": [{
            "id": "fixture", "name": "fixture", "rust_version": "1.85",
            "features": {}, "manifest_path": fixture.root.join("project/Cargo.toml"),
            "targets": [{"src_path": fixture.root.join("project/src/lib.rs")}]
        }]})
        .to_string(),
    );
    fixture.stub(
        "cargo",
        r#"case "$1" in
  metadata) printf '%s' "$METADATA" ;;
  sbom) printf '%s' '{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[{}]}' ;;
  nextest) printf '<testsuites/>\n' > "$REPORTS/tests.xml" ;;
esac"#,
    );
    fixture.stub("rustup", "");
    fs::write(fixture.root.join("build.jsonl"), "").unwrap();
    fs::write(
        fixture.root.join("project/fixture.cdx.json"),
        json!({"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"name": "fixture", "type": "library"}},
            "components": []})
        .to_string(),
    )
    .unwrap();
    fixture.stub(
        "cyclonedx",
        r#"if [[ "$1" == merge ]]; then
  while [[ "$1" != --output-file ]]; do shift; done
  printf '%s' '{"bomFormat":"CycloneDX","specVersion":"1.5",
    "metadata":{"component":{"name":"rust-release-payload"}},"components":[{}]}' > "$2"
fi"#,
    );
    fixture
}

#[test]
fn staging_produces_metadata_in_a_fresh_job() {
    let fixture = fresh_workspace();
    succeeds(&fixture.run("ci", "stage"));
    assert!(fixture.root.join("rust-release/payload.tar.gz").is_file());
    assert!(
        fixture
            .trace()
            .contains("cargo metadata --format-version 1 --locked")
    );
}

#[test]
fn declared_msrv_produces_metadata_in_a_fresh_job() {
    let fixture = fresh_workspace();
    succeeds(&fixture.run("ci", "msrv"));
    assert_eq!(
        fs::read_to_string(fixture.root.join("reports/msrv.tsv")).unwrap(),
        "fixture\t1.85\n"
    );
    assert!(
        fixture
            .trace()
            .contains("cargo metadata --format-version 1 --locked")
    );
}

#[test]
fn feature_combinations_produce_metadata_in_a_fresh_job() {
    let fixture = fresh_workspace();
    succeeds(&fixture.run("ci", "features"));
    assert!(
        fs::read_to_string(fixture.root.join("output"))
            .unwrap()
            .contains("applied=false")
    );
    assert!(
        fixture
            .trace()
            .contains("cargo metadata --format-version 1 --locked")
    );
}

#[test]
fn every_reader_reuses_job_metadata_without_rewriting_it() {
    for reader in ["stage", "msrv", "features", "quality"] {
        let fixture = fresh_workspace();
        let metadata = fixture.root.join("metadata.json");
        let original = format!("{}\n  \n", fixture.env["METADATA"]);
        fs::write(&metadata, &original).unwrap();
        succeeds(&fixture.run("ci", reader));
        assert_eq!(fs::read_to_string(&metadata).unwrap(), original, "{reader}");
        assert!(!fixture.trace().contains("cargo metadata"), "{reader}");
    }
}
