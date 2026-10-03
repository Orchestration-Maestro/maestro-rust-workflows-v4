//! Serial disposable-tree host execution and independently repeatable teardown.

mod identity;
mod installed;
mod json;
mod prepared;
mod protocol;
mod receipts;
mod step;
mod tree;

pub(super) use step::{cleanup, execute_prepared, run};
