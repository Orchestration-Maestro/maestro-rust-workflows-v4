//! Strict protocol receipts and truthful classification separate failures from kills.

use super::json::field;
use super::{identity::safe_path, installed};
use crate::checks::digests::sha256_hex;
use crate::runner::{Cmd, Failure, Outcome};
use std::fs;
use std::path::{Path, PathBuf};

/// Physical installations always belong to root:root, never runner credentials.
const INSTALLED_OWNER: (u32, u32) = (0, 0);

/// Validate schema, request binding and every typed receipt field, including failure receipts.
pub(super) fn validate(result: &str, request_digest: &str, mutant: bool) -> Outcome {
    Cmd::new("jaq -ne")
        .args(["--argjson", "r", result])
        .args(["--arg", "digest", request_digest])
        .args(["--argjson", "mutant", if mutant { "true" } else { "false" }])
        .arg(SHAPE)
        .capture()
        .map(|_| ())
        .map_err(|_| "host result schema, request binding or phase receipt is invalid".into())
}

/// Verify executable and raw log bytes, not just claimed digests in a consumer receipt.
pub(super) fn artifacts(
    result: &str,
    scratch: &Path,
    reports: &Path,
    build_root: &Path,
    installation: &Path,
) -> Outcome {
    for (kind, digest) in [("test", "test_sha256"), ("bootstrap", "bootstrap_sha256")] {
        let path = PathBuf::from(field(result, &format!(".artifacts.{kind}"))?);
        safe_path(scratch, &path)?;
        let bytes =
            fs::read(path).map_err(|error| format!("cannot read built host artifact: {error}"))?;
        if bytes.is_empty() || sha256_hex(&bytes) != field(result, &format!(".receipt.{digest}"))? {
            return Err("host built artifact digest is missing or mismatched".into());
        }
    }
    let rows = field(
        result,
        ".receipt.logs | to_entries[] | [.key,.value] | @tsv",
    )?;
    for row in rows.lines() {
        let (name, digest) = row.split_once('\t').unwrap_or_default();
        let path = reports.join(name);
        safe_path(reports, &path)?;
        let bytes =
            fs::read(path).map_err(|error| format!("cannot read raw host phase log: {error}"))?;
        if bytes.is_empty() || sha256_hex(&bytes) != digest {
            return Err("host raw log digest is missing or mismatched".into());
        }
    }
    for kind in ["test", "bootstrap"] {
        current_build(result, kind, reports, build_root)?;
    }
    installed::validate(
        result,
        installation,
        &field(result, ".receipt.bootstrap_sha256")?,
        INSTALLED_OWNER,
    )
}

/// Current Cargo JSON must identify the bytes reported, not an earlier baseline binary.
fn current_build(result: &str, kind: &str, reports: &Path, build_root: &Path) -> Outcome {
    let name = field(result, &format!(".cargo_json.{kind}"))?;
    let json = reports.join(&name);
    safe_path(reports, &json)?;
    let bytes = fs::read(&json).map_err(|error| format!("cannot read Cargo JSON: {error}"))?;
    let expected = Cmd::new("jaq -nr")
        .args(["--argjson", "r", result])
        .args(["--arg", "name", &name])
        .arg("$r.receipt.logs[$name]")
        .capture()?;
    if sha256_hex(&bytes) != expected.trim() {
        return Err("host Cargo JSON log digest is missing or mismatched".into());
    }
    let executable = Cmd::new("jaq -ser")
        .args([
            "--argjson",
            "test",
            if kind == "test" { "true" } else { "false" },
        ])
        .arg(concat!(
            "if (last.reason == \"build-finished\" and last.success == true) then ",
            "[.[] | select(.reason == \"compiler-artifact\" and .profile.test == $test ",
            "and .executable != null and ($test or (.target.kind|index(\"bin\")))) | .executable] ",
            "| unique | if length == 1 then .[0] else error(\"ambiguous artifact\") end ",
            "else error(\"build did not finish successfully\") end"
        ))
        .arg(&json)
        .capture()
        .map_err(|_| "host Cargo JSON must identify exactly one current executable")?;
    let path = PathBuf::from(executable.trim());
    safe_path(build_root, &path)?;
    let built =
        fs::read(path).map_err(|error| format!("cannot read current Cargo executable: {error}"))?;
    if sha256_hex(&built) != field(result, &format!(".receipt.{kind}_sha256"))? {
        return Err("host executable differs from the current Cargo JSON artifact".into());
    }
    Ok(())
}

/// Classification credits only a complete named behavioural failure after setup and cleanup.
pub(super) fn classify(result: &str, status: Option<i32>) -> Result<String, Failure> {
    if let Some(outcome) = match status {
        Some(124) => Some("timeout"),
        Some(137) | None => Some("oom-or-signal"),
        _ => None,
    } {
        return Ok(outcome.into());
    }
    Cmd::new("jaq -nr")
        .args(["--argjson", "r", result])
        .arg(CLASSIFY)
        .capture()
        .map(|text| text.trim().to_owned())
}

/// Strict supported shapes: no optional untyped extensions or silent additional statuses.
const SHAPE: &str = concat!(
    "def status: . == \"passed\" or . == \"failed\" or . == \"not-run\"; ",
    "def count: type == \"number\" and floor == . and . >= 0; ",
    "def strings: type == \"array\" and length == (unique|length) and ",
    "all(.[]; type == \"string\" and length > 0); ",
    "$r.receipt as $p | $r.schema == 1 and ($r|keys) == ",
    "[\"artifacts\",\"cargo_json\",\"installed_bootstrap\",",
    "\"posture\",\"receipt\",\"request_sha256\",\"schema\"] and ",
    "$r.request_sha256 == $digest and ",
    "($r.posture|keys) == [\"apparmor\",\"installed\"] and ",
    "all($r.posture[]; type == \"boolean\") and ",
    "(if $r.posture.installed then ($r.installed_bootstrap|type == \"string\" and length > 0) ",
    "else $r.installed_bootstrap == null end) and ",
    "($r.artifacts|keys) == [\"bootstrap\",\"test\"] and ",
    "all($r.artifacts[]; type == \"string\") and ",
    "($r.cargo_json|keys) == [\"bootstrap\",\"test\"] and ",
    "all($r.cargo_json[]; type == \"string\" and length > 0) and ",
    "($p|keys) == ([\"bootstrap_sha256\",\"build\",\"cleanup\",\"failed\",\"ignored\",",
    "\"logs\",\"passed\",\"phases\",\"provision\",\"selected_tests\",\"test\",",
    "\"test_sha256\"] + (if $mutant then [\"test_failure\"] else [] end) | sort) and ",
    "all([$p.build,$p.provision,$p.test,$p.cleanup][]; status) and ",
    "all([$p.passed,$p.failed,$p.ignored][]; count) and ",
    "($p.selected_tests|strings) and ",
    "(if $mutant then ($p.test_failure|strings) else true end) and ",
    "($p.phases|keys) == [\"abandon\",\"normal\",\"preparing\",",
    "\"recover_abandon\",\"recover_preparing\"] and all($p.phases[]; status) and ",
    "($p.logs|type == \"object\" and length > 0) and ",
    "all($p.logs[]; type == \"string\" and test(\"^[0-9a-f]{64}$\")) and ",
    "all([$p.test_sha256,$p.bootstrap_sha256][]; type == \"string\")"
);

/// Infrastructure classifications have precedence over a behavioural failure.
const CLASSIFY: &str = concat!(
    "$r.receipt as $p | if $p.cleanup != \"passed\" then \"cleanup-failed\" ",
    "elif $p.build != \"passed\" then \"build-failed\" ",
    "elif $p.provision != \"passed\" then \"provision-failed\" ",
    "elif ($p.selected_tests|length) == 0 or $p.ignored != 0 or ",
    "($p.selected_tests|length) != ($p.passed+$p.failed) then \"zero-or-incomplete-tests\" ",
    "elif any($p.phases[]; . == \"not-run\") or $p.test == \"not-run\" then \"incomplete\" ",
    "elif $p.test == \"passed\" and $p.failed == 0 and ",
    "all($p.phases[]; . == \"passed\") and ($p.test_failure|length) == 0 then \"survived\" ",
    "elif $p.test == \"failed\" and ($p.test_failure|length) > 0 and ",
    "([$p.test_failure[] | . as $name | select($p.selected_tests|index($name))] | length) ",
    "== $p.failed and ",
    "all($p.phases|to_entries[]; .value == \"passed\" or ",
    "(.key as $key | $p.test_failure|index($key))) and ",
    "all($p.test_failure[]; . as $name | if $p.phases|has($name) then ",
    "$p.phases[$name] == \"failed\" else ($p.selected_tests|index($name)) and ",
    "$p.failed > 0 end) then \"caught\" else \"inconsistent\" end"
);

#[cfg(test)]
mod tests {
    use super::super::json::field;
    use super::{artifacts, classify, current_build, validate};
    use crate::checks::digests::sha256_hex;
    use crate::runner::Cmd;
    use std::{env, fs, path::Path, process};

    #[test]
    fn timeouts_and_outer_signals_never_credit_a_kill() {
        assert_eq!(classify("{}", Some(124)).unwrap(), "timeout");
        assert_eq!(classify("{}", Some(137)).unwrap(), "oom-or-signal");
        assert_eq!(classify("{}", None).unwrap(), "oom-or-signal");
    }

    #[test]
    fn receipt_schema_refuses_unknown_fields_and_incomplete_failed_names() {
        let json = r#"{
  "schema": 1,
  "installed_bootstrap": null,
  "request_sha256": "request",
  "posture": {
    "installed": false,
    "apparmor": false
  },
  "artifacts": {"test":"test","bootstrap":"bootstrap"},
  "cargo_json": {"test":"cargo-test.json","bootstrap":"cargo-bootstrap.json"},
  "receipt": {
    "build": "passed",
    "provision": "passed",
    "test": "failed",
    "cleanup": "passed",
    "selected_tests": [
      "assertion"
    ],
    "passed": 0,
    "failed": 1,
    "ignored": 0,
    "phases": {
      "normal": "failed",
      "abandon": "passed",
      "preparing": "passed",
      "recover_abandon": "passed",
      "recover_preparing": "passed"
    },
    "test_sha256": "digest",
    "bootstrap_sha256": "digest",
    "logs": {
      "normal.log": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    },
    "test_failure": [
      "normal",
      "assertion"
    ]
  }
}"#;
        validate(json, "request", true).unwrap();
        assert_eq!(classify(json, Some(0)).unwrap(), "caught");
        for change in [
            ".extra=true",
            ".receipt.extra=true",
            ".schema=2",
            ".receipt.passed=0.5",
            ".receipt.phases.normal=\"unknown\"",
            "del(.receipt.cleanup)",
            ".receipt.build=\"failed\"|.installed_bootstrap=true",
            ".receipt.build=\"failed\"|.posture.installed=true|.installed_bootstrap=null",
            ".receipt.build=\"failed\"|.posture.installed=true|.installed_bootstrap=[\"path\"]",
            ".receipt.build=\"failed\"|.installed_bootstrap=\"arbitrary\"",
            ".receipt.build=\"failed\"|.posture.installed=true|.installed_bootstrap=\"\"",
            ".posture.installed=1",
            ".posture.apparmor=1",
            ".posture.extra=false",
            ".artifacts.test=false",
            ".artifacts.extra=\"other\"",
            ".cargo_json.bootstrap=false",
            ".receipt.selected_tests=[\"assertion\",\"assertion\"]",
            ".receipt.test_failure=[\"normal\",\"normal\"]",
            ".receipt.logs={}",
        ] {
            let altered = field(json, &format!("{change} | tojson")).unwrap();
            assert_eq!(
                validate(&altered, "request", true)
                    .unwrap_err()
                    .message
                    .as_deref(),
                Some("host result schema, request binding or phase receipt is invalid")
            );
        }
        assert!(validate(json, "wrong-request", true).is_err());
        for (change, expected) in [
            (".receipt.build=\"failed\"", "build-failed"),
            (".receipt.provision=\"failed\"", "provision-failed"),
            (".receipt.cleanup=\"failed\"", "cleanup-failed"),
            (".receipt.ignored=1", "zero-or-incomplete-tests"),
            (
                concat!(
                    ".receipt.selected_tests=[]|.receipt.passed=0|.receipt.failed=0|",
                    ".receipt.test=\"passed\"|.receipt.test_failure=[]|",
                    ".receipt.phases|=map_values(\"passed\")"
                ),
                "zero-or-incomplete-tests",
            ),
            (".receipt.passed=2", "zero-or-incomplete-tests"),
            (".receipt.phases.normal=\"not-run\"", "incomplete"),
            (".receipt.test_failure=[\"assertion\"]", "inconsistent"),
        ] {
            let altered = field(json, &format!("{change}|tojson")).unwrap();
            assert_eq!(classify(&altered, Some(0)).unwrap(), expected);
        }
        let altered = field(json, ".receipt.test_failure=[\"normal\"] | tojson").unwrap();
        assert_eq!(classify(&altered, Some(0)).unwrap(), "inconsistent");
    }

    #[test]
    fn built_artifact_and_raw_log_digests_are_recomputed() {
        let root = env::temp_dir().join(format!("host-artifacts-{}", process::id()));
        let scratch = root.join("scratch");
        let reports = root.join("reports");
        let build = root.join("build");
        for directory in [&scratch, &reports, &build] {
            fs::create_dir_all(directory).unwrap();
        }
        for directory in [&scratch, &build] {
            for kind in ["test", "bootstrap"] {
                fs::write(directory.join(kind), "current executable").unwrap();
            }
        }
        for kind in ["test", "bootstrap"] {
            let json = Cmd::new("jaq -cn")
                .arg("--arg")
                .arg("path")
                .arg(build.join(kind))
                .args([
                    "--argjson",
                    "test",
                    if kind == "test" { "true" } else { "false" },
                ])
                .arg(concat!(
                    "{reason:\"compiler-artifact\",profile:{test:$test},target:{kind:[\"bin\"]},",
                    "executable:$path},{reason:\"build-finished\",success:true}"
                ))
                .capture()
                .unwrap();
            fs::write(reports.join(format!("cargo-{kind}.json")), json).unwrap();
        }
        fs::write(reports.join("normal.log"), "raw output\n").unwrap();
        let executable = sha256_hex(b"current executable");
        let log = sha256_hex(b"raw output\n");
        let test_json = sha256_hex(&fs::read(reports.join("cargo-test.json")).unwrap());
        let bootstrap_json = sha256_hex(&fs::read(reports.join("cargo-bootstrap.json")).unwrap());
        let json = Cmd::new("jaq -cn")
            .arg("--arg")
            .arg("test")
            .arg(scratch.join("test"))
            .arg("--arg")
            .arg("bootstrap")
            .arg(scratch.join("bootstrap"))
            .args(["--arg", "exe", &executable])
            .args(["--arg", "log", &log])
            .args(["--arg", "tj", &test_json])
            .args(["--arg", "bj", &bootstrap_json])
            .arg(concat!(
                "{posture:{installed:false},installed_bootstrap:null,",
                "artifacts:{test:$test,bootstrap:$bootstrap},cargo_json:{",
                "test:\"cargo-test.json\",bootstrap:\"cargo-bootstrap.json\"},",
                "receipt:{test_sha256:$exe,bootstrap_sha256:$exe,",
                "logs:{\"normal.log\":$log,\"cargo-test.json\":$tj,",
                "\"cargo-bootstrap.json\":$bj}}}"
            ))
            .capture()
            .unwrap();
        let check =
            |json: &str| artifacts(json, &scratch, &reports, &root, &root.join("installation"));
        check(&json).unwrap();
        assert_empty_content_refused(&root, &json);
        fs::write(scratch.join("test"), "stale bytes").unwrap();
        assert_eq!(
            check(&json).unwrap_err().message.as_deref(),
            Some("host built artifact digest is missing or mismatched")
        );
        fs::write(scratch.join("test"), "current executable").unwrap();
        fs::write(reports.join("normal.log"), "edited raw output").unwrap();
        assert_eq!(
            check(&json).unwrap_err().message.as_deref(),
            Some("host raw log digest is missing or mismatched")
        );
        fs::write(reports.join("normal.log"), "raw output\n").unwrap();
        let altered = field(&json, "del(.receipt.logs[\"cargo-test.json\"])|tojson").unwrap();
        assert_eq!(
            check(&altered).unwrap_err().message.as_deref(),
            Some("host Cargo JSON log digest is missing or mismatched")
        );
        fs::write(scratch.join("bootstrap"), "baseline executable").unwrap();
        let altered = field(
            &json,
            &format!(
                ".receipt.bootstrap_sha256=\"{}\"|tojson",
                sha256_hex(b"baseline executable")
            ),
        )
        .unwrap();
        assert_eq!(
            check(&altered).unwrap_err().message.as_deref(),
            Some("host executable differs from the current Cargo JSON artifact")
        );
        fs::remove_dir_all(root).unwrap();
    }

    /// Empty bytes cannot be legitimized by their matching digest.
    fn assert_empty_content_refused(root: &Path, json: &str) {
        for (path, change, message) in [
            (
                root.join("scratch").join("test"),
                ".receipt.test_sha256",
                "host built artifact digest is missing or mismatched",
            ),
            (
                root.join("reports").join("normal.log"),
                ".receipt.logs[\"normal.log\"]",
                "host raw log digest is missing or mismatched",
            ),
        ] {
            let original = fs::read(&path).unwrap();
            fs::write(&path, "").unwrap();
            let altered = field(json, &format!("{change}=\"{}\"|tojson", sha256_hex(b""))).unwrap();
            assert_eq!(
                artifacts(
                    &altered,
                    &root.join("scratch"),
                    &root.join("reports"),
                    root,
                    &root.join("installation")
                )
                .unwrap_err()
                .message
                .as_deref(),
                Some(message)
            );
            fs::write(path, original).unwrap();
        }
    }

    #[test]
    fn incomplete_cargo_json_never_attests_a_current_executable() {
        let root = env::temp_dir().join(format!("host-cargo-json-{}", process::id()));
        fs::create_dir_all(&root).unwrap();
        for (kind, records) in [
            ("test", "[]"),
            (
                "test",
                r#"{"reason":"compiler-artifact","profile":{"test":true},
"executable":"first"}
{"reason":"other","success":true}"#,
            ),
            (
                "test",
                r#"{"reason":"compiler-artifact","profile":{"test":true},
"executable":"first"}
{"reason":"build-finished","success":false}"#,
            ),
            (
                "test",
                r#"{"reason":"compiler-artifact","profile":{"test":false},
"executable":"first"}
{"reason":"build-finished","success":true}"#,
            ),
            (
                "bootstrap",
                r#"{"reason":"compiler-artifact","profile":{"test":false},
"target":{"kind":["lib"]},"executable":"first"}
{"reason":"build-finished","success":true}"#,
            ),
            (
                "test",
                r#"{"reason":"compiler-artifact","profile":{"test":true},
"executable":"first"}
{"reason":"compiler-artifact","profile":{"test":true},"executable":"second"}
{"reason":"build-finished","success":true}"#,
            ),
        ] {
            fs::write(root.join("cargo-test.json"), records).unwrap();
            let json = format!(
                r#"{{"cargo_json":{{"{kind}":"cargo-test.json"}},
"receipt":{{"logs":{{"cargo-test.json":"{}"}}}}}}"#,
                sha256_hex(records.as_bytes())
            );
            assert_eq!(
                current_build(&json, kind, &root, &root)
                    .unwrap_err()
                    .message
                    .as_deref(),
                Some("host Cargo JSON must identify exactly one current executable")
            );
        }
        fs::remove_dir_all(root).unwrap();
    }
}
