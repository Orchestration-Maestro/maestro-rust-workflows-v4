//! Prepared-state bindings for internal execution and interruption-safe teardown.

use super::{
    identity,
    json::{field, read_json},
    protocol::HostRun,
};
use crate::runner::{Failure, Job, Outcome, write};

/// Serialize bindings only after exclusive checkout and scope preparation succeeded.
pub(super) fn save(host: &HostRun) -> Outcome {
    let json = host.bindings()?;
    write(&host.root.join("prepared.json"), json.as_bytes(), false)
}

/// Match retained artifacts to the live identity, refusing direct or tampered execution.
pub(super) fn load(job: &Job) -> Result<HostRun, Failure> {
    let root = job.temp.join("host-executor");
    if !root.join("prepared.json").is_file() {
        return Err("internal host execution requires gate-prepared state".into());
    }
    for file in ["prepared.json", "plan.json", "provisioner.sh", "scope.json"] {
        identity::safe_path(&job.temp, &root.join(file))?;
    }
    let plan = read_json(&root.join("plan.json"))?;
    let tree = root
        .join("checkout")
        .join(field(&plan, ".identity.directory")?);
    identity::safe_path(&root, &tree)?;
    let host = HostRun {
        root,
        tree,
        reports: job.report("host-artifacts")?,
        plan,
    };
    let live = identity::validate(job)?;
    if host.plan != live {
        return Err("host prepared-state digest or identity differs from preparation".into());
    }
    host.verify()?;
    Ok(host)
}

#[cfg(test)]
mod tests {
    use super::load;
    use crate::runner::Job;
    use std::path::PathBuf;

    #[test]
    fn internal_execution_refuses_missing_gate_prepared_state() {
        let job = Job {
            project: PathBuf::new(),
            reports: PathBuf::new(),
            temp: PathBuf::from("/nonexistent"),
        };
        assert!(load(&job).is_err());
    }
}
