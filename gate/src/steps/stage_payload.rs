//! `rust-gate stage`: the immutable release payload. Every binary the build
//! produced, every member's `CycloneDX` document and their hierarchical merge,
//! the same dependency set in SPDX, the verified packages, one tarball, its
//! provenance and the checksums of both.

use crate::checks::cargo_metadata::{EXECUTABLES, ensure_metadata, tsv_fields};
use crate::checks::checkout_paths::{canonical, strictly_inside};
use crate::checks::digests::sha256_hex;
use crate::checks::simple_names::simple;
use crate::runner::{Cmd, Failure, Job, Outcome, Step, input, path, write};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

/// What this step declares: its inputs, its tools and its reports.
pub(crate) const STEPS: &[Step] = &[Step {
    workflow: "ci",
    id: "stage",
    summary: "Stage immutable release payload",
    inputs: &["CARGO_TARGET_DIR", "GITHUB_SHA", "GITHUB_WORKSPACE"],
    tools: &["cargo metadata", "cargo sbom", "cyclonedx", "jaq", "tar"],
    reports: &["*.spdx.json", "payload.cdx.json"],
    run,
}];

/// Package name and manifest path of every workspace member.
const MEMBERS: &str =
    ".workspace_members as $members | .packages[] | select(.id as $id | $members | index($id)) |
  [.name, .manifest_path] | @tsv";

/// The envelope a per-member `CycloneDX` document must have.
const MEMBER_SBOM: &str = "
  .bomFormat == \"CycloneDX\" and .specVersion == \"1.5\" and .version == 1 and
  .metadata.component.name == $name and (.metadata.component.type | type == \"string\") and
  ((.components // []) | type == \"array\"
    and all(.[]; (.name | type == \"string\") and (.type | type == \"string\")))
";

/// The envelope the merged payload document must have.
const PAYLOAD_SBOM: &str = ".bomFormat == \"CycloneDX\" and .specVersion == \"1.5\" and
  .metadata.component.name == \"rust-release-payload\" and
  ((.components // []) | length > 0)";

/// The envelope a per-member SPDX document must have.
const SPDX: &str = ".spdxVersion == \"SPDX-2.3\" and .SPDXID == \"SPDXRef-DOCUMENT\" and
  ((.packages // []) | length > 0)";

/// Run the step: the payload directory filled artefact by artefact, then
/// sealed into the tarball, its provenance and the checksums of both.
fn run() -> Outcome {
    let job = Job::current()?;
    let root = canonical(&path("GITHUB_WORKSPACE")?)?;
    let target = canonical(&path("CARGO_TARGET_DIR")?)?;
    let payload = Payload {
        job: &job,
        directory: job.temp.join("payload"),
    };
    let release = job.temp.join("rust-release");
    for directory in [&payload.directory, &release] {
        fs::create_dir(directory)
            .map_err(|error| format!("cannot create {}: {error}", directory.display()))?;
    }
    let binaries = payload.collect_binaries(&target)?;
    let mut members = payload.collect_member_sboms(&root)?;
    let merged = payload.merge_sbom(&members)?;
    members.sort();
    payload.write_spdx(&members)?;
    fs::copy(&merged, job.report("payload.cdx.json")?)
        .map_err(|error| format!("cannot copy the payload SBOM: {error}"))?;
    payload.copy_packages(&target)?;
    payload.seal(&release, &binaries, &members)
}

/// The payload being staged: the job it belongs to, and the directory every
/// artefact is copied into before the tarball is made from it.
struct Payload<'a> {
    /// The job whose temporary directory and reports this payload uses.
    job: &'a Job,
    /// The directory the tarball is made from.
    directory: PathBuf,
}

impl Payload<'_> {
    /// Every binary the build produced, copied into the payload under its own
    /// name; a name outside the target directory or seen twice is refused.
    fn collect_binaries(&self, target: &Path) -> Result<Vec<String>, Failure> {
        let mut binaries = Vec::new();
        let executables = Cmd::new("jaq -sr")
            .arg(EXECUTABLES)
            .arg(self.job.temp.join("build.jsonl"))
            .capture()?;
        for (name, source) in named_rows(&executables, "Invalid binary name")? {
            let source = canonical(Path::new(&source))?;
            let destination = self.directory.join(&name);
            if !strictly_inside(&source, target) || destination.exists() {
                return Err("Invalid or duplicate binary output".into());
            }
            fs::copy(&source, &destination)
                .map_err(|error| format!("cannot copy {name}: {error}"))?;
            binaries.push(name);
        }
        Ok(binaries)
    }

    /// Every workspace member's `CycloneDX` document, checked and copied into the
    /// payload; the member names in the order the metadata lists them.
    fn collect_member_sboms(&self, root: &Path) -> Result<Vec<String>, Failure> {
        let mut members = Vec::new();
        let table = Cmd::new("jaq -er")
            .arg(MEMBERS)
            .arg(ensure_metadata(self.job)?)
            .capture()?;
        for (name, manifest) in named_rows(&table, "Invalid workspace package name")? {
            let manifest = canonical(Path::new(&manifest))?;
            if !strictly_inside(&manifest, root) {
                return Err("Workspace member escapes checkout".into());
            }
            let directory = manifest
                .parent()
                .ok_or("Workspace member escapes checkout")?;
            let source = canonical(&directory.join(format!("{name}.cdx.json")))?;
            if !strictly_inside(&source, root) {
                return Err("SBOM path escapes checkout".into());
            }
            Cmd::new("jaq -e --arg name")
                .arg(&name)
                .arg(MEMBER_SBOM)
                .arg(&source)
                .capture()
                .map_err(|_| "Invalid CycloneDX JSON envelope or component metadata")?;
            fs::copy(&source, self.directory.join(format!("{name}.cdx.json")))
                .map_err(|error| format!("cannot copy the SBOM of {name}: {error}"))?;
            members.push(name);
        }
        some_member(&members)?;
        Ok(members)
    }

    /// One document describing the payload as a whole. An attestation binds a
    /// single subject, so the per-member files cannot serve as its SBOM; a
    /// hierarchical merge keeps each member nested under a root component
    /// instead of flattening them into duplicate entries.
    fn merge_sbom(&self, members: &[String]) -> Result<PathBuf, Failure> {
        let merged = self.directory.join("payload.cdx.json");
        let member_sboms: Vec<PathBuf> = members
            .iter()
            .map(|name| self.directory.join(format!("{name}.cdx.json")))
            .collect();
        Cmd::new("cyclonedx merge --input-files")
            .args(&member_sboms)
            .args([
                "--output-format",
                "json",
                "--output-version",
                "v1_5",
                "--hierarchical",
            ])
            .args(["--name", "rust-release-payload", "--version"])
            .arg(input("GITHUB_SHA")?)
            .arg("--output-file")
            .arg(&merged)
            .run()?;
        Cmd::new("cyclonedx validate --input-file")
            .arg(&merged)
            .args(["--input-format", "json"])
            .run()?;
        Cmd::new("jaq -e")
            .arg(PAYLOAD_SBOM)
            .arg(&merged)
            .capture()
            .map_err(|_| "Merged payload SBOM is not a usable CycloneDX 1.5 document")?;
        Ok(merged)
    }

    /// The same dependency set in SPDX, because consumer tooling is split
    /// between the two formats and one a consumer cannot read is no bill of
    /// materials at all. Generated natively per member rather than converted
    /// from the merged `CycloneDX` document: `cyclonedx convert` loses nested
    /// components from a hierarchical merge and duplicates shared ones from a
    /// flat merge, and a silently incomplete SBOM is worse than none because it
    /// looks like an answer. Native generation also carries the SPDX
    /// relationship graph, which the conversion drops entirely. No SPDX merge
    /// step exists because nothing attests these documents. Both formats come
    /// from the one member list, so a member cannot be described by one and
    /// missing from the other.
    fn write_spdx(&self, members: &[String]) -> Outcome {
        for member in members {
            let spdx = self.directory.join(format!("{member}.spdx.json"));
            Cmd::new("cargo sbom --cargo-package")
                .arg(member)
                .args(["--output-format", "spdx_json_2_3", "--project-directory"])
                .arg(&self.job.project)
                .stdout_to(&spdx)?;
            Cmd::new("jaq -e")
                .arg(SPDX)
                .arg(&spdx)
                .capture()
                .map_err(|_| {
                    format!("SPDX document for {member} is not a usable SPDX 2.3 document")
                })?;
            fs::copy(&spdx, self.job.report(&format!("{member}.spdx.json"))?)
                .map_err(|error| format!("cannot copy the SPDX document of {member}: {error}"))?;
        }
        Ok(())
    }

    /// Every verified package archive, copied into the payload; a symlink in
    /// the package directory is refused rather than followed.
    fn copy_packages(&self, target: &Path) -> Outcome {
        let Ok(entries) = fs::read_dir(target.join("package")) else {
            return Ok(());
        };
        for entry in entries {
            let entry = entry.map_err(|error| format!("cannot read the packages: {error}"))?;
            let source = entry.path();
            if source
                .extension()
                .is_none_or(|extension| extension != "crate")
            {
                continue;
            }
            if entry.file_type().is_ok_and(|kind| kind.is_symlink()) {
                return Err("Package archive must not be a symlink".into());
            }
            fs::copy(&source, self.directory.join(entry.file_name()))
                .map_err(|error| format!("cannot copy {}: {error}", source.display()))?;
        }
        Ok(())
    }

    /// The tarball, its provenance and the checksums of both, from the lists of
    /// what went into it.
    fn seal(&self, release: &Path, binaries: &[String], members: &[String]) -> Outcome {
        // The archive is named relative to the release directory: a GNU tar
        // on Windows reads `C:\...` as a remote host.
        Cmd::new("tar -czf payload.tar.gz -C")
            .arg(&self.directory)
            .arg(".")
            .cwd(release)
            .run()?;
        let binaries_list = self.job.temp.join("binaries");
        let sboms_list = self.job.temp.join("sboms");
        write(&binaries_list, list(binaries).as_bytes(), false)?;
        let sboms: Vec<String> = members
            .iter()
            .map(|name| format!("{name}.cdx.json"))
            .collect();
        write(&sboms_list, list(&sboms).as_bytes(), false)?;
        Cmd::new("jaq -n --arg revision")
            .arg(input("GITHUB_SHA")?)
            .arg("--rawfile")
            .arg("binaries")
            .arg(&binaries_list)
            .arg("--rawfile")
            .arg("sboms")
            .arg(&sboms_list)
            .arg(
                "{revision: $revision, target: \"x86_64-unknown-linux-gnu\",
         binaries: ($binaries | split(\"\\n\") | map(select(length > 0)) | sort),
         sboms: ($sboms | split(\"\\n\") | map(select(length > 0)) | sort)}",
            )
            .stdout_to(&release.join("provenance.json"))?;
        // The checksums in sha256sum's own format, computed here so that no
        // platform needs a sha256sum of its own.
        let mut sums = String::new();
        for name in ["payload.tar.gz", "provenance.json"] {
            let bytes = fs::read(release.join(name))
                .map_err(|error| format!("cannot read {name}: {error}"))?;
            let _ = writeln!(sums, "{}  {name}", sha256_hex(&bytes));
        }
        write(&release.join("SHA256SUMS"), sums.as_bytes(), false)
    }
}

/// The rows of a jaq table, `<name>\t<path>` per line, with every name held to
/// the one simple-name rule; `invalid` is the refusal for a name that is not
/// one, which differs between a binary and a workspace package.
fn named_rows(table: &str, invalid: &'static str) -> Result<Vec<(String, String)>, Failure> {
    let mut rows = Vec::new();
    for line in table.lines() {
        let mut fields = tsv_fields(line).into_iter();
        let (name, value) = (
            fields.next().unwrap_or_default(),
            fields.next().unwrap_or_default(),
        );
        if !simple(&name, "_", "_-") {
            return Err(invalid.into());
        }
        rows.push((name, value));
    }
    Ok(rows)
}

/// Refuse a payload with no member to describe.
fn some_member(members: &[String]) -> Outcome {
    if members.is_empty() {
        return Err("No workspace SBOM generated".into());
    }
    Ok(())
}

/// One name per line, the shape the payload's file lists are written in.
fn list(names: &[String]) -> String {
    let mut text = String::new();
    for name in names {
        let _ = writeln!(text, "{name}");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::some_member;

    #[test]
    fn a_payload_without_a_member_is_refused() {
        assert!(some_member(&["fixture".to_owned()]).is_ok());
        let error = some_member(&[]).unwrap_err();
        assert_eq!(
            error.message.as_deref(),
            Some("No workspace SBOM generated")
        );
    }
}
