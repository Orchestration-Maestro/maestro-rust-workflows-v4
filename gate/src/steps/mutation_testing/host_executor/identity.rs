//! Revalidate the complete host plan before invoking consumer administration.

use super::super::scope;
use super::json::read_json;
use crate::checks::digests::sha256_hex;
use crate::checks::mutation_host::host_policy;
use crate::runner::{Cmd, Failure, Job, input};
use std::fs;
use std::path::{Component, Path, PathBuf};

/// A plan is data only within runner temp, with no symlink components.
pub(super) fn safe_path(root: &Path, path: &Path) -> Result<(), Failure> {
    scope_root(root)?;
    let relative = path
        .strip_prefix(root)
        .map_err(|_| "host protocol path escapes its scope")?;
    let mut current = root.to_path_buf();
    for part in relative.components() {
        if !matches!(part, Component::Normal(_)) {
            return Err("host protocol path escapes its scope".into());
        }
        current.push(part);
        let metadata = fs::symlink_metadata(&current)
            .map_err(|error| format!("cannot inspect host path: {error}"))?;
        if metadata.file_type().is_symlink() {
            return Err("host protocol path contains a symlink".into());
        }
    }
    Ok(())
}

/// Create one directory at a time, refusing pre-existing links before any write.
pub(super) fn create_directory(root: &Path, path: &Path) -> Result<(), Failure> {
    scope_root(root)?;
    let relative = path
        .strip_prefix(root)
        .map_err(|_| "host protocol path escapes its scope")?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err("host protocol path escapes its scope".into());
        }
        current.push(component);
        if !current.exists() {
            fs::create_dir(&current)
                .map_err(|error| format!("cannot create host directory: {error}"))?;
        }
        let metadata = fs::symlink_metadata(&current)
            .map_err(|error| format!("cannot inspect host directory: {error}"))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("host protocol directory is not a real directory".into());
        }
    }
    Ok(())
}

/// The scope anchor itself cannot redirect otherwise normal children through a link.
fn scope_root(root: &Path) -> Result<(), Failure> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("cannot inspect host scope root: {error}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("host protocol scope root is not a real directory".into());
    }
    Ok(())
}

/// Validate tested source, tracked policy, script, tools, workflow and attempt together.
pub(super) fn validate(job: &Job) -> Result<String, Failure> {
    let path = PathBuf::from(input("MUTATION_HOST_PLAN")?);
    safe_path(&job.temp, &path)?;
    let plan = read_json(&path)?;
    let policy = host_policy(&job.project)?.ok_or("host executor requires a tested-head policy")?;
    let head = Cmd::new("git rev-parse HEAD").cwd(&job.project).capture()?;
    let sources = sources(job, &policy.files)?;
    let packages = scope::engine_packages(&job.project, &policy.files)?;
    let result = Cmd::new("jaq -ne")
        .args(["--argjson", "p", &plan])
        .args(["--argjson", "sources", &sources])
        .args(["--argjson", "files", &json_strings(&policy.files)?])
        .args(["--argjson", "features", &json_strings(&policy.features)?])
        .args(["--argjson", "packages", &json_strings(&packages)?])
        .args([
            "--arg",
            "config",
            &scope::configuration_digest(&job.project)?,
        ])
        .args(["--arg", "directory", &scope::normalized_directory()?])
        .args(["--arg", "sha", &input("GITHUB_SHA")?])
        .args(["--arg", "head", head.trim()])
        .args(["--arg", "run", &input("GITHUB_RUN_ID")?])
        .args(["--arg", "attempt", &input("GITHUB_RUN_ATTEMPT")?])
        .args(["--arg", "compiler", &input("RUSTUP_TOOLCHAIN")?])
        .args(["--arg", "tool", &input("CARGO_MUTANTS_VERSION")?])
        .args(["--arg", "workflow", &input("WORKFLOW_REVISION")?])
        .args(["--arg", "policy", &policy.digest])
        .args(["--arg", "script", &policy.provisioner])
        .args(["--arg", "script_hash", &policy.provisioner_digest])
        .arg(concat!(
            "$p.schema == 1 and ($p|keys) == [\"features\",\"files\",\"identity\",\"mutants\",",
            "\"packages\",\"policy_sha256\",\"provisioner\",\"provisioner_sha256\",\"schema\",",
            "\"source_sha256\",\"workflow_revision\"] and ",
            "$p.files == $files and $p.features == $features and $p.packages == $packages and ",
            "($p.identity|keys) == [\"attempt\",\"cargo_mutants_version\",\"config_sha256\",",
            "\"diff_sha256\",\"directory\",\"first_parent\",\"mutant_count\",\"run_id\",\"sha\",",
            "\"shard_count\",\"toolchain\"] and ",
            "$p.identity.config_sha256 == $config and $p.identity.directory == $directory and ",
            "$p.identity.sha == $sha and $head == $sha and ",
            "$p.identity.run_id == $run and $p.identity.attempt == $attempt and ",
            "$p.identity.toolchain == $compiler and $p.identity.cargo_mutants_version == $tool ",
            "and $tool == \"27.1.0\" and $p.workflow_revision == $workflow and ",
            "$p.policy_sha256 == $policy and $p.provisioner == $script and ",
            "$p.provisioner_sha256 == $script_hash and $p.source_sha256 == $sources and ",
            "all([$p.identity.mutant_count,$p.identity.shard_count][]; type == \"number\" ",
            "and . >= 0 and floor == .) and ",
            "($p.mutants|length) > 0 and ",
            "($p.mutants|length) == ($p.mutants|unique_by([.package,.name])|length) and ",
            "([$p.mutants[].file]|unique|sort) == ($files|sort) and ",
            "all($p.mutants[]; (.name|type == \"string\" and length > 0) and ",
            "(.package as $name | $packages|index($name)) != null and ",
            "(.diff|type == \"string\" and length > 0) and ",
            "(.function.function_name|type == \"string\" and length > 0) and ",
            ".function.span.start.line <= .span.start.line and ",
            ".function.span.end.line >= .span.end.line)"
        ))
        .capture();
    result.map_err(|_| "host executor identity, policy or source differs from its plan")?;
    let parent = match Cmd::new("git rev-parse --verify -q HEAD^1")
        .cwd(&job.project)
        .capture()
    {
        Ok(parent) => parent,
        Err(error) if error.code == 1 && error.message.is_none() => String::new(),
        Err(error) => return Err(error),
    };
    if super::json::field(&plan, ".identity.first_parent // \"\"")? != parent.trim() {
        return Err("host executor first parent differs from its plan".into());
    }
    Ok(plan)
}

/// Serialize only already validated policy values through the existing JSON reader.
fn json_strings(values: &[String]) -> Result<String, Failure> {
    Cmd::new("jaq -cn")
        .arg("$ARGS.positional")
        .arg("--args")
        .args(values)
        .capture()
}

/// Recompute source digests from the actual tested checkout.
fn sources(job: &Job, files: &[String]) -> Result<String, Failure> {
    let mut command = Cmd::new("jaq -cn").arg("$ARGS.named");
    for file in files {
        let bytes = fs::read(job.project.join(file)).map_err(|error| format!("{file}: {error}"))?;
        command = command.args(["--arg", file, &sha256_hex(&bytes)]);
    }
    command.capture()
}

#[cfg(test)]
mod tests {
    use super::{create_directory, safe_path};
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    use std::path::Path;
    use std::{env, fs, process};

    #[test]
    fn scope_paths_refuse_parent_components_and_other_roots() {
        assert!(safe_path(Path::new("/tmp/a"), Path::new("/tmp/b")).is_err());
        assert!(safe_path(Path::new("/tmp"), Path::new("/tmp/../etc")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn protocol_directory_creation_never_follows_a_symlink() {
        let root = env::temp_dir().join(format!("host-directories-{}", process::id()));
        fs::create_dir_all(&root).unwrap();
        symlink(env::temp_dir(), root.join("link")).unwrap();
        assert_eq!(
            safe_path(&root.join("link"), &root.join("link/outside"))
                .unwrap_err()
                .message
                .as_deref(),
            Some("host protocol scope root is not a real directory")
        );
        assert_eq!(
            create_directory(&root, &root.join("link/outside"))
                .unwrap_err()
                .message
                .as_deref(),
            Some("host protocol directory is not a real directory")
        );
        fs::remove_dir_all(root).unwrap();
    }
}
