// amail-gateway shared library.

pub mod base;
pub mod board;
pub mod core;

// Re-export mailin types used by advanced edition,
// so amail-advanced doesn't need a direct mailin dependency.
pub use mailin::{Action, Response, SessionBuilder};
