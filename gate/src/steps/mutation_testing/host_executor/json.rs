//! JSON values remain data, never shell command fragments.

use crate::runner::{Cmd, Failure};
use std::path::Path;

/// Read JSON through the existing pinned reader, preserving the compact validated value.
pub(super) fn read_json(path: &Path) -> Result<String, Failure> {
    Cmd::new("jaq -c").arg(".").arg(path).capture()
}

/// Extract a literal JSON query from already controlled JSON bytes.
pub(super) fn field(json: &str, query: &str) -> Result<String, Failure> {
    Cmd::new("jaq -nr")
        .args(["--argjson", "p", json])
        .arg(format!("$p | {query}"))
        .capture()
        .map(|value| value.strip_suffix('\n').unwrap_or(&value).to_owned())
}

#[cfg(test)]
mod tests {
    use super::field;

    #[test]
    fn protocol_fields_preserve_json_instead_of_evaluating_shell_text() {
        assert_eq!(field("{\"x\":\"$(false)\"}", ".x").unwrap(), "$(false)");
    }
}
