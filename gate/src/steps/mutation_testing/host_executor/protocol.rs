//! Gate-controlled schema-1 requests and the one reviewed script invocation.

use super::{
    identity::{create_directory, safe_path},
    json::{field, read_json},
    receipts,
};
use crate::checks::digests::sha256_hex;
use crate::runner::{Cmd, Failure, Outcome, input, write};
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write as _};
use std::path::PathBuf;

/// The executor's persistent scope survives a killed executor for always-run teardown.
pub(super) struct HostRun {
    /// Private executor root in runner temp.
    pub(super) root: PathBuf,
    /// Disposable project inside the checkout.
    pub(super) tree: PathBuf,
    /// Retained artifact root, separate from disposable scratch.
    pub(super) reports: PathBuf,
    /// Validated plan bytes, used as the single identity source.
    pub(super) plan: String,
}

impl HostRun {
    /// Every script invocation must use the same scope and script that preparation bound.
    pub(super) fn verify(&self) -> Outcome {
        for file in ["prepared.json", "plan.json", "provisioner.sh", "scope.json"] {
            safe_path(&self.root, &self.root.join(file))?;
        }
        if read_json(&self.root.join("prepared.json"))? != self.bindings()? {
            return Err("host prepared-state digest or identity differs from preparation".into());
        }
        Ok(())
    }

    /// One strict record binds every resource-owning input, plus live source and attempt.
    pub(super) fn bindings(&self) -> Result<String, Failure> {
        let mut command = Cmd::new("jaq -cn")
            .args(["--arg", "sha", &input("GITHUB_SHA")?])
            .args(["--arg", "run", &input("GITHUB_RUN_ID")?])
            .args(["--arg", "attempt", &input("GITHUB_RUN_ATTEMPT")?]);
        for (name, file) in [
            ("plan_sha256", "plan.json"),
            ("scope_sha256", "scope.json"),
            ("provisioner_sha256", "provisioner.sh"),
        ] {
            let bytes = fs::read(self.root.join(file))
                .map_err(|error| format!("cannot bind prepared state: {error}"))?;
            command = command.args(["--arg", name, &sha256_hex(&bytes)]);
        }
        command.arg("$ARGS.named + {schema:1}").capture()
    }

    /// Bind scenario, patched bytes, locations and fixed host posture to the script request.
    pub(super) fn request(
        &self,
        scenario: &str,
        mutant: &str,
        patched: &str,
        posture: &str,
    ) -> Result<PathBuf, Failure> {
        self.verify()?;
        let scratch = self.root.join("scratch").join(scenario);
        if scenario != "cleanup" {
            create_directory(&self.root, &scratch)?;
        }
        let report = self.reports.join(scenario);
        create_directory(&self.reports, &report)?;
        let scope = self.root.join("scope.json");
        let kind = if scenario.starts_with("mutant-") {
            "mutant"
        } else {
            scenario
        };
        let json = Cmd::new("jaq -cn")
            .args(["--argjson", "plan", &self.plan])
            .args(["--argjson", "mutant", mutant])
            .args(["--argjson", "posture", posture])
            .args(["--arg", "scenario", kind])
            .args(["--arg", "scenario_id", scenario])
            .args(["--arg", "source", patched])
            .arg("--arg")
            .arg("scratch")
            .arg(&scratch)
            .arg("--arg")
            .arg("reports")
            .arg(&report)
            .arg("--arg")
            .arg("scope")
            .arg(&scope)
            .args([
                "--arg",
                "scope_hash",
                &sha256_hex(
                    &fs::read(&scope).map_err(|error| format!("cannot read scope: {error}"))?,
                ),
            ])
            .arg(concat!(
                "{schema:1,scenario:$scenario,scenario_id:$scenario_id,features:$plan.features,",
                "identity:$plan.identity,",
                "policy_sha256:$plan.policy_sha256,provisioner_sha256:$plan.provisioner_sha256,",
                "source_sha256:$plan.source_sha256,mutant:$mutant,patched_source_sha256:$source,",
                "scratch:$scratch,reports:$reports,baseline_posture:$posture,",
                "scope_manifest:$scope,scope_sha256:$scope_hash}"
            ))
            .capture()?;
        let path = report.join("request.json");
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.is_file() {
                    return Err("host request is not a regular file".into());
                }
                fs::remove_file(&path)
                    .map_err(|error| format!("cannot replace host request: {error}"))?;
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(format!("cannot inspect host request: {error}").into()),
        }
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .and_then(|mut file| file.write_all(json.as_bytes()))
            .map_err(|error| format!("cannot create exclusive host request: {error}"))?;
        Ok(path)
    }

    /// Run every mandatory phase through the script's protocol and preserve both raw streams.
    pub(super) fn scenario(
        &self,
        scenario: &str,
        mutant: &str,
        patched: &str,
        posture: &str,
    ) -> Result<(String, String), Failure> {
        let request = self.request(scenario, mutant, patched, posture)?;
        let result = request.with_file_name("result.json");
        let digest = sha256_hex(
            &fs::read(&request).map_err(|error| format!("cannot read request: {error}"))?,
        );
        let sha = field(&self.plan, ".identity.sha")?;
        let source = Cmd::new("git diff --binary")
            .arg(&sha)
            .cwd(&self.tree)
            .capture()?;
        let command = Cmd::new("timeout --kill-after=1m 30m bash")
            .arg(self.root.join("provisioner.sh"))
            .arg("--gate-host-v1")
            .arg(&request)
            .arg(&result)
            .cwd(&self.tree);
        let output = command.capture_output()?;
        let mut log = output.stdout;
        log.extend_from_slice(&output.stderr);
        log.extend_from_slice(format!("\nexit={:?}\n", output.status.code()).as_bytes());
        write(&request.with_file_name("command.log"), &log, false)?;
        let interruption = match output.status.code() {
            Some(124) => Some("timeout"),
            Some(137) | None => Some("oom-or-signal"),
            _ => None,
        };
        if Cmd::new("git rev-parse HEAD")
            .cwd(&self.tree)
            .capture()?
            .trim()
            != sha
            || Cmd::new("git diff --binary")
                .arg(&sha)
                .cwd(&self.tree)
                .capture()?
                != source
        {
            eprintln!("source-changed");
            return Ok((
                "null".into(),
                interruption.unwrap_or("source-changed").into(),
            ));
        }
        let receipt = self.receipt(scenario, (&result, &digest), posture, output.status.code());
        if let Some(outcome) = interruption {
            match &receipt {
                Ok((_, diagnostic)) => eprintln!("host process {outcome}; receipt: {diagnostic}"),
                Err(error) => eprintln!("host process {outcome}; receipt: {:?}", error.message),
            }
            return Ok(("null".into(), outcome.into()));
        }
        receipt
    }

    /// Receipt problems remain diagnostics when the process was interrupted.
    fn receipt(
        &self,
        scenario: &str,
        binding: (&PathBuf, &str),
        posture: &str,
        status: Option<i32>,
    ) -> Result<(String, String), Failure> {
        let (result, digest) = binding;
        if !result.exists() {
            return Ok((
                "null".into(),
                match status {
                    Some(124) => "timeout",
                    Some(137) | None => "oom-or-signal",
                    _ => "missing-receipt",
                }
                .into(),
            ));
        }
        safe_path(&self.reports, result)?;
        let json = read_json(result)?;
        if receipts::validate(&json, digest, scenario.starts_with("mutant-")).is_err() {
            return Ok(("null".into(), "invalid-receipt".into()));
        }
        let classification = receipts::classify(&json, status)?;
        if field(&json, ".receipt.build")? == "passed" {
            let installation = PathBuf::from(field(
                &read_json(&self.root.join("scope.json"))?,
                ".installation",
            )?);
            if let Err(error) = receipts::artifacts(
                &json,
                &self.root.join("scratch").join(scenario),
                &self.reports,
                &self.root,
                &installation,
            ) {
                eprintln!(
                    "{}",
                    error.message.unwrap_or_else(|| format!(
                        "host artifact validation failed with status {}",
                        error.code
                    ))
                );
                return Ok((json, "invalid-artifacts".into()));
            }
        }
        if posture != "null" && field(&json, ".posture | tojson")? != posture {
            return Ok((json, "posture-changed".into()));
        }
        Ok((json, classification))
    }

    /// Idempotent cleanup uses the original copied script and immutable gate-owned scope.
    pub(super) fn cleanup(&self) -> Outcome {
        let request = self.request("cleanup", "null", "", "null")?;
        let result = request.with_file_name("result.json");
        if result.exists() {
            safe_path(&self.reports, &result)?;
            fs::remove_file(&result)
                .map_err(|error| format!("cannot discard old cleanup receipt: {error}"))?;
        }
        let digest = sha256_hex(
            &fs::read(&request).map_err(|error| format!("cannot read cleanup request: {error}"))?,
        );
        let sha = field(&self.plan, ".identity.sha")?;
        // Inspection errors cannot prevent the safety script from running.
        let head = Cmd::new("git rev-parse HEAD").cwd(&self.tree).capture();
        let source = Cmd::new("git diff --binary")
            .arg(&sha)
            .cwd(&self.tree)
            .capture();
        let output = Cmd::new("timeout --kill-after=1m 120s bash")
            .arg(self.root.join("provisioner.sh"))
            .arg("--gate-host-v1")
            .arg(&request)
            .arg(&result)
            .cwd(&self.root)
            .capture_output()?;
        let mut logs = output.stdout;
        logs.extend_from_slice(&output.stderr);
        write(&request.with_file_name("command.log"), &logs, false)?;
        if !output.status.success() || !result.exists() {
            return Err("host independent cleanup failed or is missing".into());
        }
        let after = Cmd::new("git rev-parse HEAD").cwd(&self.tree).capture()?;
        let changed = Cmd::new("git diff --binary")
            .arg(&sha)
            .cwd(&self.tree)
            .capture()?;
        if head?.trim() != sha || after.trim() != sha || source? != changed {
            return Err("host cleanup changed source or HEAD".into());
        }
        safe_path(&self.reports, &result)?;
        Cmd::new("jaq -e")
            .args(["--arg", "digest", &digest])
            .arg("--slurpfile")
            .arg("scope")
            .arg(self.root.join("scope.json"))
            .arg(concat!(
                "(keys == [\"absent\",\"cleanup\",\"removed\",\"request_sha256\",\"schema\"]) and ",
                ".schema == 1 and .cleanup == \"passed\" and .request_sha256 == $digest and ",
                "(.removed+.absent|sort) == ($scope[0].resources|sort)"
            ))
            .arg(&result)
            .capture()
            .map(|_| ())
            .map_err(|_| "host cleanup receipt escapes or omits its owned scope".into())
    }
}

#[cfg(test)]
mod tests {
    use super::HostRun;
    use std::path::PathBuf;

    #[test]
    fn missing_preparation_is_refused_before_request_or_resource_writes() {
        let host = HostRun {
            root: PathBuf::from("/nonexistent"),
            tree: PathBuf::new(),
            reports: PathBuf::new(),
            plan: String::new(),
        };
        assert!(host.verify().is_err());
    }
}
