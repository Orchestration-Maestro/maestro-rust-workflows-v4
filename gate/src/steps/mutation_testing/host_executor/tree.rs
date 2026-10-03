//! Exact listed patches in an isolated Git checkout, restored without preserving mtimes.

use super::json::field;
use crate::checks::digests::sha256_hex;
use crate::runner::{Cmd, Failure, Outcome};
use std::fs;
use std::path::Path;

/// Restore every tracked byte and reject a provisioner changing tracked inputs.
pub(super) fn restore(tree: &Path, sha: &str) -> Outcome {
    Cmd::new("git reset --hard").arg(sha).cwd(tree).capture()?;
    let status = Cmd::new("git diff --name-only")
        .arg(sha)
        .cwd(tree)
        .capture()?;
    if Cmd::new("git rev-parse HEAD").cwd(tree).capture()?.trim() != sha
        || !status.trim().is_empty()
    {
        return Err("host source restoration did not recover the baseline".into());
    }
    Ok(())
}

/// Apply only a single-file patch and compare the actual diff to cargo-mutants' listing.
pub(super) fn apply(tree: &Path, mutant: &str, sha: &str) -> Result<String, Failure> {
    let file = field(mutant, ".file")?;
    let original = field(mutant, ".diff")?;
    let name = field(mutant, ".name")?;
    let label = name
        .rsplit_once(": ")
        .map(|(_, label)| label)
        .unwrap_or_default();
    let mut lines = original.splitn(3, '\n');
    if lines.next() != Some(format!("--- {file}").as_str())
        || lines.next() != Some(format!("+++ {label}").as_str())
    {
        return Err("host patch header differs from its discovered source".into());
    }
    // cargo-mutants labels the new side with the mutation description, not a filename.
    let diff = format!(
        "--- a/{file}\n+++ b/{file}\n{}",
        lines.next().unwrap_or_default()
    );
    let listed = Cmd::new("git apply --numstat -")
        .stdin_bytes(diff.as_bytes())
        .capture()?;
    let rows: Vec<_> = listed.lines().collect();
    if rows.len() != 1 || rows.first().and_then(|row| row.split('\t').nth(2)) != Some(file.as_str())
    {
        return Err("host patch changes more than its exact owned source".into());
    }
    Cmd::new("git apply --check -")
        .cwd(tree)
        .stdin_bytes(diff.as_bytes())
        .capture()?;
    Cmd::new("git apply -")
        .cwd(tree)
        .stdin_bytes(diff.as_bytes())
        .capture()?;
    let changed = Cmd::new("git diff --name-only")
        .arg(sha)
        .cwd(tree)
        .capture()?;
    if changed.trim() != file {
        return Err("host patch changes more than its exact owned source".into());
    }
    let bytes = fs::read(tree.join(file))
        .map_err(|error| format!("cannot hash patched source: {error}"))?;
    Ok(sha256_hex(&bytes))
}

#[cfg(test)]
mod tests {
    use super::apply;
    use std::path::Path;

    #[test]
    fn discovered_patch_headers_and_single_file_scope_are_required() {
        for (diff, message) in [
            (
                "bad header",
                "host patch header differs from its discovered source",
            ),
            (
                concat!(
                    "--- src/host.rs\\n+++ replace host with ()\\n@@ -1 +1 @@\\n-true\\n+false\\n",
                    "--- a/src/other.rs\\n+++ b/src/other.rs\\n@@ -1 +1 @@\\n-true\\n+false\\n"
                ),
                "host patch changes more than its exact owned source",
            ),
        ] {
            let mutant = format!(
                r#"{{"file":"src/host.rs",
"name":"src/host.rs:1:1: replace host with ()","diff":"{diff}"}}"#
            );
            assert_eq!(
                apply(Path::new("/nonexistent"), &mutant, "plan")
                    .unwrap_err()
                    .message
                    .as_deref(),
                Some(message)
            );
        }
    }
}
