//! What several steps read out of Cargo's own records: jaq programs over
//! `cargo metadata` and the build's JSON messages, and the rows they print.

use crate::runner::{Cmd, Failure, Job};
use std::path::PathBuf;

/// Reuse this job's Cargo records, producing them when no earlier step did.
pub(crate) fn ensure_metadata(job: &Job) -> Result<PathBuf, Failure> {
    let metadata = job.temp.join("metadata.json");
    if !metadata.exists() {
        Cmd::new("cargo metadata --format-version 1 --locked")
            .cwd(&job.project)
            .stdout_to(&metadata)?;
    }
    Ok(metadata)
}

/// Binary name and executable path of every compiler artifact.
pub(crate) const EXECUTABLES: &str =
    ".[] | select(.reason == \"compiler-artifact\" and .executable != null) |
  [.target.name, .executable] | @tsv";

/// The fields of one row jaq's `@tsv` printed, its escapes undone: `\\`,
/// `\t`, `\n` and `\r`. On Windows every path Cargo reports holds
/// backslashes, which the row carries doubled.
pub(crate) fn tsv_fields(row: &str) -> Vec<String> {
    row.split('\t').map(unescaped).collect()
}

/// One `@tsv` field with its escapes undone.
fn unescaped(field: &str) -> String {
    let mut text = String::with_capacity(field.len());
    let mut characters = field.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            text.push(character);
            continue;
        }
        match characters.next() {
            Some('t') => text.push('\t'),
            Some('n') => text.push('\n'),
            Some('r') => text.push('\r'),
            Some(other) => text.push(other),
            None => text.push('\\'),
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::tsv_fields;

    #[test]
    fn a_row_s_escapes_are_undone_field_by_field() {
        // As jaq prints `["core", "C:\\Users\\a", "a\nb"] | @tsv`.
        let row = "core\tC:\\\\Users\\\\a\ta\\nb";
        assert_eq!(tsv_fields(row), ["core", "C:\\Users\\a", "a\nb"]);
        assert_eq!(tsv_fields("x\ty"), ["x", "y"]);
        assert_eq!(tsv_fields("end\\"), ["end\\"]);
    }
}
