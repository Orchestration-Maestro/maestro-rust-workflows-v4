//! Bind the physically installed bootstrap to the current Cargo-produced bytes.

use super::{identity::safe_path, json::field};
use crate::checks::digests::sha256_hex;
use crate::runner::Outcome;
use std::{
    fs,
    path::{Path, PathBuf},
};

/// Production passes root's mandatory identity; private fixtures pass their actual owner.
pub(super) fn validate(
    result: &str,
    installation: &Path,
    digest: &str,
    owner: (u32, u32),
) -> Outcome {
    let kind = field(result, ".installed_bootstrap|type")?;
    if field(result, ".posture.installed")? == "false" {
        return if kind == "null" {
            Ok(())
        } else {
            Err("uninstalled host receipt must not name an installed bootstrap".into())
        };
    }
    if kind != "string" || field(result, ".installed_bootstrap")?.is_empty() {
        return Err("installed host receipt is missing its bootstrap path".into());
    }
    let path = PathBuf::from(field(result, ".installed_bootstrap")?);
    if !path.starts_with(installation.join(digest)) {
        return Err("host installed bootstrap path is outside its digest installation".into());
    }
    // Walk from the filesystem root, not merely the installation anchor, using lstat throughout.
    safe_path(Path::new("/"), &path)
        .map_err(|_| "host installed bootstrap path is unsafe or missing")?;
    file_posture(&path, installation, owner)?;
    let bytes =
        fs::read(&path).map_err(|error| format!("cannot read installed bootstrap: {error}"))?;
    if sha256_hex(&bytes) != digest {
        return Err(
            "host installed bootstrap differs from the current Cargo JSON executable".into(),
        );
    }
    Ok(())
}

/// Immutable owned directories make the checked file immune to runner-side replacement.
#[cfg(unix)]
fn file_posture(path: &Path, installation: &Path, owner: (u32, u32)) -> Outcome {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect installed bootstrap: {error}"))?;
    if !metadata.is_file() {
        return Err("host installed bootstrap is not a regular file".into());
    }
    if (metadata.uid(), metadata.gid()) != owner {
        return Err(
            "host installed bootstrap ownership does not match its required identity".into(),
        );
    }
    if metadata.mode() & 0o7777 != 0o555 {
        return Err("host installed bootstrap mode is not 0555".into());
    }
    for directory in path
        .ancestors()
        .skip(1)
        .take_while(|directory| directory.starts_with(installation))
    {
        let metadata = fs::symlink_metadata(directory)
            .map_err(|error| format!("cannot inspect installation directory: {error}"))?;
        if !metadata.is_dir()
            || (metadata.uid(), metadata.gid()) != owner
            || metadata.mode() & 0o7777 != 0o755
        {
            return Err(
                "host installation directory must have its required ownership and 0755 mode".into(),
            );
        }
    }
    Ok(())
}

/// This owner is available only on the Ubuntu execution platform.
#[cfg(not(unix))]
fn file_posture(_path: &Path, _installation: &Path, _owner: (u32, u32)) -> Outcome {
    Err("host bootstrap installation requires Unix ownership metadata".into())
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::validate;
    use crate::checks::digests::sha256_hex;
    use crate::runner::Cmd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::{env, fs, io, path::PathBuf, process};

    /// Current bytes and their digest-named installed copy belong to this fixture identity.
    fn fixture(name: &str) -> io::Result<(PathBuf, PathBuf, String)> {
        let root = fs::canonicalize(env::temp_dir())?
            .join(format!("host-installed-{}-{name}", process::id()));
        let digest = sha256_hex(b"current bootstrap");
        let directory = root.join(&digest);
        let path = directory.join("bootstrap");
        fs::create_dir_all(&directory)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755))?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755))?;
        fs::write(&path, b"current bootstrap")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o555))?;
        let json = Cmd::new("jaq -cn")
            .arg("--arg")
            .arg("path")
            .arg(&path)
            .arg("{posture:{installed:true},installed_bootstrap:$path}")
            .capture()
            .map_err(|error| io::Error::other(format!("{error:?}")))?;
        Ok((root, path, json))
    }

    #[test]
    fn installed_bootstrap_refuses_stale_bytes_wrong_owner_and_wrong_mode() {
        let (root, path, json) = fixture("metadata").unwrap();
        let meta = fs::symlink_metadata(&root).unwrap();
        let owner = (meta.uid(), meta.gid());
        let digest = sha256_hex(b"current bootstrap");
        validate(&json, &root, &digest, owner).unwrap();
        assert_eq!(
            validate(&json, &root, &digest, (owner.0 + 1, owner.1))
                .unwrap_err()
                .message
                .as_deref(),
            Some("host installed bootstrap ownership does not match its required identity")
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            validate(&json, &root, &digest, owner)
                .unwrap_err()
                .message
                .as_deref(),
            Some("host installed bootstrap mode is not 0555")
        );
        fs::write(&path, b"baseline bootstrap").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o555)).unwrap();
        assert_eq!(
            validate(&json, &root, &digest, owner)
                .unwrap_err()
                .message
                .as_deref(),
            Some("host installed bootstrap differs from the current Cargo JSON executable")
        );
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            validate(&json, &root, &digest, owner)
                .unwrap_err()
                .message
                .as_deref(),
            Some("host installation directory must have its required ownership and 0755 mode")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn installation_binding_refuses_symlinks_escapes_null_and_uninstalled_paths() {
        let (root, path, json) = fixture("binding").unwrap();
        let meta = fs::symlink_metadata(&root).unwrap();
        let owner = (meta.uid(), meta.gid());
        let digest = sha256_hex(b"current bootstrap");
        let null = "{\"posture\":{\"installed\":true},\"installed_bootstrap\":null}";
        assert_eq!(
            validate(null, &root, &digest, owner)
                .unwrap_err()
                .message
                .as_deref(),
            Some("installed host receipt is missing its bootstrap path")
        );
        let uninstalled = json.replace("true", "false");
        assert_eq!(
            validate(&uninstalled, &root, &digest, owner)
                .unwrap_err()
                .message
                .as_deref(),
            Some("uninstalled host receipt must not name an installed bootstrap")
        );
        let outside = json.replace(&path.display().to_string(), "/outside/bootstrap");
        assert_eq!(
            validate(&outside, &root, &digest, owner)
                .unwrap_err()
                .message
                .as_deref(),
            Some("host installed bootstrap path is outside its digest installation")
        );
        fs::remove_file(&path).unwrap();
        symlink("/bin/true", &path).unwrap();
        assert_eq!(
            validate(&json, &root, &digest, owner)
                .unwrap_err()
                .message
                .as_deref(),
            Some("host installed bootstrap path is unsafe or missing")
        );
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert_eq!(
            validate(&json, &root, &digest, owner)
                .unwrap_err()
                .message
                .as_deref(),
            Some("host installed bootstrap is not a regular file")
        );
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
#[cfg(not(unix))]
mod platform_tests {
    use super::file_posture;
    use std::path::Path;

    #[test]
    fn non_unix_installation_refuses_missing_ownership_metadata() {
        assert_eq!(
            file_posture(Path::new("unused"), Path::new("unused"), (0, 0))
                .unwrap_err()
                .message
                .as_deref(),
            Some("host bootstrap installation requires Unix ownership metadata")
        );
    }
}
